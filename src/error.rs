use std::{error, fmt, io};

#[derive(Debug)]
pub struct Error(ErrorImpl);

#[derive(Debug)]
enum ErrorImpl {
    Io(io::Error),
    Transport(String),
    Userauth(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ssh error: {:?}", self.0)
    }
}

impl error::Error for Error {}

impl Error {
    pub(crate) fn io(err: io::Error) -> Self {
        Self(ErrorImpl::Io(err))
    }

    pub(crate) fn transport(msg: impl Into<String>) -> Self {
        Self(ErrorImpl::Transport(msg.into()))
    }

    pub(crate) fn userauth(msg: impl Into<String>) -> Self {
        Self(ErrorImpl::Userauth(msg.into()))
    }
}
