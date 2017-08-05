use std::error::Error as StdError;
use std::fmt;
use std::io;

/// KCP protocol errors
#[derive(Debug)]
pub enum Error {
    ConvInconsistent(u32, u32),
    InvalidMtuSisze(usize),
    InvalidSegmentSize(usize),
    InvalidSegmentDataSize(usize, usize),
    IoError(io::Error),
    NeedUpdate,
    RecvQueueEmpty,
    UnexpectedEof,
    UnsupportCmd(u8),
    UserBufTooBig,
    UserBufTooSmall,
}

impl StdError for Error {
    fn description(&self) -> &str {
        match *self {
            Error::ConvInconsistent(..) => "segment's conv number is inconsistent.",
            Error::InvalidMtuSisze(_) => "invalid mtu size.",
            Error::InvalidSegmentSize(_) => "invalid segment size.",
            Error::InvalidSegmentDataSize(..) => "segment's data size is invalid.",
            Error::IoError(ref e) => e.description(),
            Error::NeedUpdate => "need call kcp's update method.",
            Error::RecvQueueEmpty => "receive queue is empty.",
            Error::UnexpectedEof => "unexpected eof",
            Error::UnsupportCmd(_) => "cmd is unsupport.",
            Error::UserBufTooBig => "user's buffer too big.",
            Error::UserBufTooSmall => "user's buffer too small.",
        }
    }

    fn cause(&self) -> Option<&StdError> {
        match *self {
            Error::IoError(ref e) => Some(e),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            Error::ConvInconsistent(ref s, ref o) => {
                write!(f, "segment's conv number is inconsistent, our's is {}, the other's is {}.", *s, *o)
            }
            Error::InvalidMtuSisze(ref e) => write!(f, "invalid mtu size of {}", *e),
            Error::InvalidSegmentSize(ref e) => write!(f, "invalid segment size of {}.", *e),
            Error::InvalidSegmentDataSize(ref s, ref o) => {
                write!(f, "segment's data size is invalid, size in header is {}, the actual size is {}.", *s, *o)
            }
            Error::IoError(ref e) => e.fmt(f),
            Error::UnsupportCmd(ref e) => write!(f, "cmd {} is unsupport.", *e),
            ref e => write!(f, "{}", e.description()),
        }
    }
}
