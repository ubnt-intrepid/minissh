// defined in https://tools.ietf.org/html/rfc4253#section-12
pub(crate) const SSH_MSG_DISCONNECT: u8 = 1;
pub(crate) const SSH_MSG_IGNORE: u8 = 2;
pub(crate) const SSH_MSG_UNIMPLEMENTED: u8 = 3;
pub(crate) const SSH_MSG_DEBUG: u8 = 4;
//pub(crate) const SSH_MSG_SERVICE_REQUEST: u8 = 5;
pub(crate) const SSH_MSG_SERVICE_ACCEPT: u8 = 6;
pub(crate) const SSH_MSG_KEXINIT: u8 = 20;
pub(crate) const SSH_MSG_NEWKEYS: u8 = 21;

// defined in https://tools.ietf.org/html/rfc5656#section-7.1
pub(crate) const SSH_MSG_KEX_ECDH_INIT: u8 = 30;
pub(crate) const SSH_MSG_KEX_ECDH_REPLY: u8 = 31;

// defined in https://tools.ietf.org/html/rfc4252#section-6
pub(crate) const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
pub(crate) const SSH_MSG_USERAUTH_FAILURE: u8 = 51;
pub(crate) const SSH_MSG_USERAUTH_SUCCESS: u8 = 52;
pub(crate) const SSH_MSG_USERAUTH_BANNER: u8 = 53;

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
