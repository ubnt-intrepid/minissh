use crate::{
    consts,
    transport::Transport,
    util::{get_ssh_string, put_ssh_string},
};
use bytes::{Buf, BufMut, Bytes};
use futures::{
    ready,
    task::{self, Poll},
};
use std::{cmp, collections::HashMap, num};
use tokio::io::{AsyncRead, AsyncWrite};

pub struct Connection {
    initial_window_size: u32,
    maximum_packet_size: u32,
    channels: HashMap<ChannelId, Channel>,
    next_channel_id: num::Wrapping<u32>,
    recv_buf: Vec<u8>,
}

impl Default for Connection {
    fn default() -> Self {
        Self {
            initial_window_size: 0,
            maximum_packet_size: 0x8000,
            channels: HashMap::new(),
            next_channel_id: num::Wrapping(0),
            recv_buf: vec![],
        }
    }
}

impl Connection {
    pub fn set_initial_window_size(&mut self, size: u32) {
        self.initial_window_size = size;
    }

    pub fn set_maximum_packet_size(&mut self, size: u32) {
        self.maximum_packet_size = size;
    }

    /// Request to open a session channel.
    pub fn poll_channel_open_session<T>(
        &mut self,
        cx: &mut task::Context<'_>,
        transport: &mut Transport<T>,
    ) -> Poll<Result<ChannelId, crate::Error>>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        ready!(transport.poll_send_ready(cx))?;

        let sender_channel = self.allocate_channel();

        transport.fill(24, |mut buf| {
            buf.put_u8(consts::SSH_MSG_CHANNEL_OPEN);
            put_ssh_string(&mut buf, b"session");
            buf.put_u32(sender_channel.0);
            buf.put_u32(self.initial_window_size);
            buf.put_u32(self.maximum_packet_size);
            debug_assert!(buf.is_empty());
        })?;

        Poll::Ready(Ok(sender_channel))
    }

    fn allocate_channel(&mut self) -> ChannelId {
        use std::collections::hash_map::Entry;

        // FIXME: limit loop count
        loop {
            let sender_id = ChannelId(self.next_channel_id.0);
            if let Entry::Vacant(entry) = self.channels.entry(sender_id) {
                entry.insert(Channel {
                    state: ChannelState::Opening,
                    sender_id,
                    sender_window_size: self.initial_window_size,
                    sender_maximum_packet_size: self.maximum_packet_size,
                    recipient_id: RecipientChannelId(0),
                    recipient_window_size: 0,
                    recipient_max_packet_size: 0,
                    recipient_eof: false,
                });
                return sender_id;
            }

            self.next_channel_id += num::Wrapping(1);
        }
    }

    pub fn poll_request_exec<T>(
        &mut self,
        cx: &mut task::Context<'_>,
        transport: &mut Transport<T>,
        channel: ChannelId,
        command: &str,
    ) -> Poll<Result<(), crate::Error>>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let channel = self
            .channels
            .get_mut(&channel)
            .ok_or_else(|| crate::Error::connection("invalid channel id"))?;

        ready!(transport.poll_send_ready(cx))?;

        transport.fill(18 + command.len(), |mut buf| {
            buf.put_u8(consts::SSH_MSG_CHANNEL_REQUEST);
            buf.put_u32(channel.recipient_id.0);
            put_ssh_string(&mut buf, b"exec");
            buf.put_u8(0); // want_reply=FALSE
            put_ssh_string(&mut buf, command.as_ref());
            debug_assert!(buf.is_empty());
        })?;

        // TODO: mark send state.

        Poll::Ready(Ok(()))
    }

    pub fn poll_close<T>(
        &mut self,
        cx: &mut task::Context<'_>,
        transport: &mut Transport<T>,
        channel: ChannelId,
    ) -> Poll<Result<(), crate::Error>>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let channel = match self.channels.get_mut(&channel) {
            Some(ch) => ch,
            None => return Poll::Ready(Ok(())), // do nothing
        };

        ready!(transport.poll_send_ready(cx))?;

        transport.fill(5, |mut buf| {
            buf.put_u8(consts::SSH_MSG_CHANNEL_CLOSE);
            buf.put_u32(channel.recipient_id.0);
        })?;

        channel.state = ChannelState::Closing;

        Poll::Ready(Ok(()))
    }

    pub fn poll_window_adjust<T>(
        &mut self,
        cx: &mut task::Context<'_>,
        transport: &mut Transport<T>,
        channel: ChannelId,
        additional: u32,
    ) -> Poll<Result<(), crate::Error>>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let channel = self
            .channels
            .get_mut(&channel)
            .ok_or_else(|| crate::Error::connection("invalid channel id"))?;

        ready!(transport.poll_send_ready(cx))?;

        transport.fill(9, |mut buf| {
            buf.put_u8(consts::SSH_MSG_CHANNEL_WINDOW_ADJUST);
            buf.put_u32(channel.recipient_id.0);
            buf.put_u32(additional);
        })?;

        channel.recipient_window_size = channel.recipient_window_size.saturating_add(additional);

        Poll::Ready(Ok(()))
    }

    pub fn poll_recv<T>(
        &mut self,
        cx: &mut task::Context<'_>,
        transport: &mut Transport<T>,
    ) -> Poll<Result<Response, crate::Error>>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        ready!(transport.poll_flush(cx))?;

        loop {
            let mut payload = ready!(transport.poll_recv(cx, &mut self.recv_buf))?;
            tracing::trace!("Handle incoming message");
            match payload.get_u8() {
                // Global request described in https://tools.ietf.org/html/rfc4254#section-4
                consts::SSH_MSG_GLOBAL_REQUEST => {
                    tracing::trace!("--> GLOBAL_REQUEST");
                    // According to RFC, the recipient of this message is expected to reply with
                    // SSH_MSG_REQUEST_SUCCESS, SSH_MSG_REQUEST_FAILURE or request-specific message.
                    // It means that additional state management is required, and hence such kind
                    // of requests are ignored here for simplicity.
                    continue;
                }
                consts::SSH_MSG_REQUEST_SUCCESS | consts::SSH_MSG_REQUEST_FAILURE => {
                    tracing::trace!("--> REQUEST_SUCCESS|REQUEST_FAILURE");
                    // ignore silently since no global request is supported from the client.
                    continue;
                }

                consts::SSH_MSG_CHANNEL_OPEN_CONFIRMATION => {
                    tracing::trace!("--> CHANNEL_OPEN_CONFIRMATION");
                    let sender_id = ChannelId(payload.get_u32()); // 'recipient channel' in RFC
                    let recipient_id = RecipientChannelId(payload.get_u32()); // 'sender channel' in RFC
                    let recipient_window_size = payload.get_u32();
                    let recipient_max_packet_size = payload.get_u32();
                    tracing::trace!("    recipient_window_size = {}", recipient_window_size);
                    tracing::trace!("    recipient_max_packet = {}", recipient_max_packet_size);

                    if let Some(channel) = self.channels.get_mut(&sender_id) {
                        channel.state = ChannelState::OpenConfirmed;
                        channel.recipient_id = recipient_id;
                        channel.recipient_window_size = recipient_window_size;
                        channel.recipient_max_packet_size = recipient_max_packet_size;

                        return Poll::Ready(Ok(Response::Channel(
                            sender_id,
                            ChannelResponse::OpenConfirmation,
                        )));
                    }
                }
                consts::SSH_MSG_CHANNEL_OPEN_FAILURE => {
                    tracing::trace!("--> CHANNEL_OPEN_FAILURE");
                    let sender_id = ChannelId(payload.get_u32());
                    let reason_code = payload.get_u32();
                    let description = get_ssh_string(&mut payload);
                    let language_tag = get_ssh_string(&mut payload);

                    let _channel = match self.channels.remove(&sender_id) {
                        Some(channel) => channel,
                        None => continue, // ignore silently
                    };

                    return Poll::Ready(Ok(Response::Channel(
                        sender_id,
                        ChannelResponse::OpenFailure {
                            reason_code,
                            description,
                            language_tag,
                        },
                    )));
                }

                consts::SSH_MSG_CHANNEL_WINDOW_ADJUST => {
                    tracing::trace!("--> CHANNEL_WINDOW_ADJUST");
                    let sender_id = ChannelId(payload.get_u32()); // 'recipient channel' in RFC
                    let additional = payload.get_u32();
                    tracing::trace!("    sender_id = {:?}", sender_id);
                    tracing::trace!("    additional = {}", additional);

                    let channel = match self.channels.get_mut(&sender_id) {
                        Some(channel) => channel,
                        None => continue, // ignore silently
                    };

                    channel.sender_window_size =
                        channel.sender_window_size.saturating_add(additional);

                    // TODO: notify window adjustment to caller.
                    continue;
                }

                consts::SSH_MSG_CHANNEL_DATA => {
                    tracing::trace!("--> CHANNEL_DATA");
                    let sender_id = ChannelId(payload.get_u32()); // 'recipient channel' in RFC
                    let length = payload.get_u32();
                    assert!(payload.remaining() >= length as usize);

                    let channel = match self.channels.get_mut(&sender_id) {
                        Some(channel) => channel,
                        None => continue, // ignore silently
                    };

                    if channel.recipient_eof {
                        // ignore since recipient has already been sent EOF.
                        continue;
                    }

                    // calculate the available data length
                    let limit = cmp::min(
                        channel.recipient_window_size as usize,
                        channel.recipient_max_packet_size as usize,
                    );
                    tracing::trace!("limit = {}", limit);
                    let mut payload = Buf::take(payload, limit);

                    channel.recipient_window_size = channel
                        .recipient_window_size
                        .saturating_sub(payload.remaining() as u32);

                    let data = payload.copy_to_bytes(payload.remaining());

                    return Poll::Ready(Ok(Response::Channel(
                        sender_id,
                        ChannelResponse::Data(data),
                    )));
                }

                consts::SSH_MSG_CHANNEL_EOF => {
                    tracing::trace!("--> CHANNEL_EOF");
                    let sender_id = ChannelId(payload.get_u32()); // 'recipient channel' in RFC

                    let channel = match self.channels.get_mut(&sender_id) {
                        Some(channel) => channel,
                        None => continue, // ignore silently
                    };

                    if channel.recipient_eof {
                        // ignore since recipient has already been sent EOF.
                        continue;
                    }

                    channel.recipient_eof = true;
                    return Poll::Ready(Ok(Response::Channel(sender_id, ChannelResponse::Eof)));
                }

                consts::SSH_MSG_CHANNEL_CLOSE => {
                    tracing::trace!("--> CHANNEL_CLOSE");
                    let sender_id = ChannelId(payload.get_u32()); // 'recipient channel' in RFC

                    let _channel = match self.channels.remove(&sender_id) {
                        Some(channel) => channel,
                        None => continue, // ignore silently
                    };

                    return Poll::Ready(Ok(Response::Channel(sender_id, ChannelResponse::Close)));
                }

                typ @ consts::SSH_MSG_CHANNEL_SUCCESS | typ @ consts::SSH_MSG_CHANNEL_FAILURE => {
                    tracing::trace!("--> CHANNEL_SUCCESS|CHANNEL_FAILURE");
                    let sender_id = ChannelId(payload.get_u32()); // 'recipient channel' in RFC

                    if let Some(_channel) = self.channels.get_mut(&sender_id) {
                        // TODO: check whether ongoing requests corresponding to this message exists.

                        let resp = match typ {
                            consts::SSH_MSG_CHANNEL_SUCCESS => ChannelResponse::RequestSuccess,
                            consts::SSH_MSG_CHANNEL_FAILURE => ChannelResponse::RequestFailure,
                            _ => unreachable!(),
                        };

                        return Poll::Ready(Ok(Response::Channel(sender_id, resp)));
                    }
                }

                typ => {
                    tracing::warn!("ignore packet (typ = {})", typ);
                    continue;
                }
            }
        }
    }
}

#[non_exhaustive]
pub enum Response {
    Channel(ChannelId, ChannelResponse),
}

#[non_exhaustive]
pub enum ChannelResponse {
    OpenConfirmation,
    OpenFailure {
        reason_code: u32,
        description: Vec<u8>,
        language_tag: Vec<u8>,
    },
    RequestSuccess,
    RequestFailure,
    Data(Bytes),
    Eof,
    Close,
}

// === Channel ===

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ChannelId(u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct RecipientChannelId(u32);

struct Channel {
    sender_id: ChannelId,
    sender_window_size: u32,
    sender_maximum_packet_size: u32,

    recipient_id: RecipientChannelId,
    recipient_window_size: u32,
    recipient_max_packet_size: u32,
    recipient_eof: bool,

    state: ChannelState,
}

enum ChannelState {
    Opening,
    OpenConfirmed,
    Closing,
}
