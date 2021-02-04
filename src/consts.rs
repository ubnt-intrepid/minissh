#![allow(dead_code)]

// transport layer message types, defined in https://tools.ietf.org/html/rfc4253#section-12
pub(crate) const SSH_MSG_DISCONNECT: u8 = 1;
pub(crate) const SSH_MSG_IGNORE: u8 = 2;
pub(crate) const SSH_MSG_UNIMPLEMENTED: u8 = 3;
pub(crate) const SSH_MSG_DEBUG: u8 = 4;
pub(crate) const SSH_MSG_SERVICE_REQUEST: u8 = 5;
pub(crate) const SSH_MSG_SERVICE_ACCEPT: u8 = 6;
pub(crate) const SSH_MSG_KEXINIT: u8 = 20;
pub(crate) const SSH_MSG_NEWKEYS: u8 = 21;

// reason codes in disconnection message, definied in https://tools.ietf.org/html/rfc4253#section-11.1
pub(crate) const SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT: u32 = 1;
pub(crate) const SSH_DISCONNECT_PROTOCOL_ERROR: u32 = 2;
pub(crate) const SSH_DISCONNECT_KEY_EXCHANGE_FAILED: u32 = 3;
pub(crate) const SSH_DISCONNECT_RESERVED: u32 = 4;
pub(crate) const SSH_DISCONNECT_MAC_ERROR: u32 = 5;
pub(crate) const SSH_DISCONNECT_COMPRESSION_ERROR: u32 = 6;
pub(crate) const SSH_DISCONNECT_SERVICE_NOT_AVAILABLE: u32 = 7;
pub(crate) const SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED: u32 = 8;
pub(crate) const SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE: u32 = 9;
pub(crate) const SSH_DISCONNECT_CONNECTION_LOST: u32 = 10;
pub(crate) const SSH_DISCONNECT_BY_APPLICATION: u32 = 11;
pub(crate) const SSH_DISCONNECT_TOO_MANY_CONNECTIONS: u32 = 12;
pub(crate) const SSH_DISCONNECT_AUTH_CANCELLED_BY_USER: u32 = 13;
pub(crate) const SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE: u32 = 14;
pub(crate) const SSH_DISCONNECT_ILLEGAL_USER_NAME: u32 = 15;

// defined in https://tools.ietf.org/html/rfc5656#section-7.1
pub(crate) const SSH_MSG_KEX_ECDH_INIT: u8 = 30;
pub(crate) const SSH_MSG_KEX_ECDH_REPLY: u8 = 31;

// defined in https://tools.ietf.org/html/rfc4252#section-6
pub(crate) const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
pub(crate) const SSH_MSG_USERAUTH_FAILURE: u8 = 51;
pub(crate) const SSH_MSG_USERAUTH_SUCCESS: u8 = 52;
pub(crate) const SSH_MSG_USERAUTH_BANNER: u8 = 53;
// defined in https://tools.ietf.org/html/rfc4252#section-7
pub(crate) const SSH_MSG_USERAUTH_PK_OK: u8 = 60;
// defined in https://tools.ietf.org/html/rfc4252#section-8
pub(crate) const SSH_MSG_USERAUTH_PASSWD_CHANGEREQ: u8 = 60;

// defined in https://tools.ietf.org/html/rfc4254#section-9
pub(crate) const SSH_MSG_GLOBAL_REQUEST: u8 = 80;
pub(crate) const SSH_MSG_REQUEST_SUCCESS: u8 = 81;
pub(crate) const SSH_MSG_REQUEST_FAILURE: u8 = 82;
pub(crate) const SSH_MSG_CHANNEL_OPEN: u8 = 90;
pub(crate) const SSH_MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;
pub(crate) const SSH_MSG_CHANNEL_OPEN_FAILURE: u8 = 92;
pub(crate) const SSH_MSG_CHANNEL_WINDOW_ADJUST: u8 = 93;
pub(crate) const SSH_MSG_CHANNEL_DATA: u8 = 94;
pub(crate) const SSH_MSG_CHANNEL_EXTENDED_DATA: u8 = 95;
pub(crate) const SSH_MSG_CHANNEL_EOF: u8 = 96;
pub(crate) const SSH_MSG_CHANNEL_CLOSE: u8 = 97;
pub(crate) const SSH_MSG_CHANNEL_REQUEST: u8 = 98;
pub(crate) const SSH_MSG_CHANNEL_SUCCESS: u8 = 99;
pub(crate) const SSH_MSG_CHANNEL_FAILURE: u8 = 100;

// SSH agent protocol numbers defined in https://tools.ietf.org/html/draft-miller-ssh-agent-04#section-7.1
pub(crate) const SSH_AGENT_FAILURE: u8 = 5;
pub(crate) const SSH_AGENT_SUCCESS: u8 = 6;
pub(crate) const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub(crate) const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub(crate) const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
pub(crate) const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
pub(crate) const SSH_AGENTC_ADD_IDENTITY: u8 = 17;
pub(crate) const SSH_AGENTC_REMOVE_IDENTITY: u8 = 18;
pub(crate) const SSH_AGENTC_REMOVE_ALL_IDENTITIES: u8 = 19;
pub(crate) const SSH_AGENTC_ADD_SMARTCARD_KEY: u8 = 20;
pub(crate) const SSH_AGENTC_REMOVE_SMARTCARD_KEY: u8 = 21;
pub(crate) const SSH_AGENTC_LOCK: u8 = 22;
pub(crate) const SSH_AGENTC_UNLOCK: u8 = 23;
pub(crate) const SSH_AGENTC_ADD_ID_CONSTRAINED: u8 = 25;
pub(crate) const SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED: u8 = 26;
pub(crate) const SSH_AGENTC_EXTENSION: u8 = 27;
pub(crate) const SSH_AGENT_EXTENSION_FAILURE: u8 = 28;

// SSH agent key constraint numbers defined in https://tools.ietf.org/html/draft-miller-ssh-agent-04#section-7.2
pub(crate) const SSH_AGENT_CONSTRAIN_LIFETIME: u8 = 1;
pub(crate) const SSH_AGENT_CONSTRAIN_CONFIRM: u8 = 2;
pub(crate) const SSH_AGENT_CONSTRAIN_EXTENSION: u8 = 255;

// SSH agent signature flags defined in https://tools.ietf.org/html/draft-miller-ssh-agent-04#section-7.3
pub(crate) const SSH_AGENT_RSA_SHA2_256: u8 = 0x02;
pub(crate) const SSH_AGENT_RSA_SHA2_512: u8 = 0x04;
