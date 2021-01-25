// ref: https://tools.ietf.org/html/draft-miller-ssh-agent-04

use crate::{
    consts,
    util::{get_ssh_string, put_ssh_string},
};
use bytes::{Buf, BufMut};
use futures::{
    ready,
    task::{self, Poll},
};
use std::{
    env,
    ffi::OsString,
    io,
    os::unix::prelude::*,
    path::{Path, PathBuf},
    pin::Pin,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::UnixStream,
};

const SSH_AGENT_PATH_ENV_NAME: &str = "SSH_AUTH_SOCK";
const DEFAULT_CAPACITY: usize = 8 * 1024;

pub struct Agent<T> {
    stream: T,
    send_buf: Box<[u8]>,
    filled: usize,
    send_state: SendState,
    recv_state: RecvState,
}

enum SendState {
    Ready,
    Writing(usize),
    Flushing,
}

enum RecvState {
    ReadingLength { buf: [u8; 4], filled: usize },
    ReadingMessage { buf: Vec<u8>, filled: usize },
}

impl<T> Agent<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(stream: T) -> Self {
        Self::with_capacity(stream, DEFAULT_CAPACITY)
    }

    pub fn with_capacity(stream: T, capacity: usize) -> Self {
        Self {
            stream,
            send_buf: vec![0u8; capacity].into_boxed_slice(),
            filled: 0,
            send_state: SendState::Ready,
            recv_state: RecvState::ReadingLength {
                buf: [0u8; 4],
                filled: 0,
            },
        }
    }

    pub fn poll_flush(&mut self, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        let mut stream = Pin::new(&mut self.stream);

        loop {
            match self.send_state {
                SendState::Ready if self.filled == 0 => return Poll::Ready(Ok(())),
                SendState::Ready => {
                    self.send_state = SendState::Writing(0);
                }

                SendState::Writing(ref mut written) => {
                    let mut write_buf = &self.send_buf[*written..self.filled];
                    while write_buf.has_remaining() {
                        let amt = ready!(stream.as_mut().poll_write(cx, write_buf))?;
                        write_buf.advance(amt);
                        *written += amt;
                    }
                    self.send_state = SendState::Flushing;
                }

                SendState::Flushing => {
                    ready!(stream.as_mut().poll_flush(cx))?;
                    self.filled = 0;
                    self.send_state = SendState::Ready;
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }

    fn send_message<B>(&mut self, message: &mut B) -> io::Result<()>
    where
        B: Buf,
    {
        assert!(matches!(self.send_state, SendState::Ready));

        let packet_len = 4 + message.remaining();
        let mut remains = &mut self.send_buf[self.filled..self.filled + packet_len];

        remains.put_u32(message.remaining() as u32);
        message.copy_to_slice(remains);

        self.filled += packet_len;

        Ok(())
    }

    pub fn send_request_identities(&mut self) -> io::Result<()> {
        let msg: &[u8] = &[consts::SSH_AGENTC_REQUEST_IDENTITIES];
        self.send_message(&mut &msg[..])?;
        Ok(())
    }

    pub fn send_sign_request<B>(
        &mut self,
        identity: &Identity,
        data: &mut B,
        flags: SignFlag,
    ) -> io::Result<()>
    where
        B: Buf,
    {
        let mut header = vec![];
        header.put_u8(consts::SSH_AGENTC_SIGN_REQUEST);
        put_ssh_string(&mut header, &identity.key_blob[..]);

        let data_len = (data.remaining() as u32).to_be_bytes();
        let flags = flags.to_be_bytes();

        let mut message = Buf::chain(&header[..], &data_len[..])
            .chain(data)
            .chain(&flags[..]);

        self.send_message(&mut message)?;

        Ok(())
    }

    pub fn poll_recv(&mut self, cx: &mut task::Context<'_>) -> Poll<io::Result<Response>> {
        ready!(self.poll_flush(cx))?;

        let mut stream = Pin::new(&mut self.stream);
        loop {
            match self.recv_state {
                RecvState::ReadingLength {
                    ref mut buf,
                    ref mut filled,
                } => {
                    tracing::trace!("--> ReadingLength(filled = {})", filled);

                    let mut read_buf = ReadBuf::new(&mut buf[..]);
                    read_buf.set_filled(*filled);

                    loop {
                        let rem = read_buf.remaining();
                        if rem != 0 {
                            ready!(stream.as_mut().poll_read(cx, &mut read_buf))?;
                            *filled = read_buf.filled().len();
                            if read_buf.remaining() == rem {
                                return Poll::Ready(Err(unexpected_eof()));
                            }
                        } else {
                            break;
                        }
                    }

                    let message_len = u32::from_be_bytes(*buf);

                    self.recv_state = RecvState::ReadingMessage {
                        buf: vec![0u8; message_len as usize],
                        filled: 0,
                    };
                }

                RecvState::ReadingMessage {
                    ref mut buf,
                    ref mut filled,
                } => {
                    tracing::trace!("--> ReadingMessage(filled = {})", filled);

                    let mut read_buf = ReadBuf::new(&mut buf[..]);
                    read_buf.set_filled(*filled);

                    loop {
                        let rem = read_buf.remaining();
                        if rem != 0 {
                            ready!(stream.as_mut().poll_read(cx, &mut read_buf))?;
                            *filled = read_buf.filled().len();
                            if read_buf.remaining() == rem {
                                return Poll::Ready(Err(unexpected_eof()));
                            }
                        } else {
                            break;
                        }
                    }

                    let buf = match std::mem::replace(
                        &mut self.recv_state,
                        RecvState::ReadingLength {
                            buf: [0u8; 4],
                            filled: 0,
                        },
                    ) {
                        RecvState::ReadingMessage { buf, .. } => buf,
                        _ => unreachable!(),
                    };
                    let mut buf = &buf[..];

                    let response = match buf.get_u8() {
                        consts::SSH_AGENT_IDENTITIES_ANSWER => {
                            let nkeys = buf.get_u32();
                            let mut identities = Vec::with_capacity(nkeys as usize);
                            for _ in 0..nkeys {
                                let key_blob = get_ssh_string(&mut buf);
                                let comment = get_ssh_string(&mut buf);
                                identities.push(Identity {
                                    key_blob,
                                    comment: OsString::from_vec(comment),
                                })
                            }
                            Response::Identities(identities)
                        }

                        consts::SSH_AGENT_SIGN_RESPONSE => {
                            let signature = get_ssh_string(&mut buf);
                            Response::SignResponse(signature)
                        }

                        typ => {
                            tracing::warn!("ignore unknown message: {}", typ);
                            continue;
                        }
                    };

                    return Poll::Ready(Ok(response));
                }
            }
        }
    }
}

impl Agent<UnixStream> {
    pub async fn connect() -> io::Result<Self> {
        let agent_path = env::var_os(SSH_AGENT_PATH_ENV_NAME)
            .map(PathBuf::from)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("missing environment variable: {}", SSH_AGENT_PATH_ENV_NAME),
                )
            })?;
        Self::connect_to(agent_path).await
    }

    pub async fn connect_to(agent_path: impl AsRef<Path>) -> io::Result<Self> {
        let stream = UnixStream::connect(agent_path).await?;
        Ok(Self::new(stream))
    }
}

pub type SignFlag = u32;

#[derive(Debug)]
#[non_exhaustive]
pub enum Response {
    Identities(Vec<Identity>),
    SignResponse(Vec<u8>),
}

#[derive(Debug)]
#[non_exhaustive]
pub struct Identity {
    pub key_blob: Vec<u8>,
    pub comment: OsString,
}

fn unexpected_eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "early EOF")
}
