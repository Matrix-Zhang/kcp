use std::error::Error as StdError;
use std::io::{self, ErrorKind};

/// KCP protocol errors
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("conv inconsistent, expected {0}, found {1}")]
    ConvInconsistent(u32, u32),
    #[error("invalid mtu {0}")]
    InvalidMtu(usize),
    #[error("invalid segment size {0}")]
    InvalidSegmentSize(usize),
    #[error("invalid segment data size, expected {0}, found {1}")]
    InvalidSegmentDataSize(usize, usize),
    #[error("{0}")]
    IoError(
        #[from]
        #[source]
        io::Error,
    ),
    #[error("need to call update() once")]
    NeedUpdate,
    #[error("recv queue is empty")]
    RecvQueueEmpty,
    #[error("expecting fragment")]
    ExpectingFragment,
    #[error("command {0} is not supported")]
    UnsupportedCmd(u8),
    #[error("user's send buffer is too big")]
    UserBufTooBig,
    #[error("user's recv buffer is too small")]
    UserBufTooSmall,
}

fn make_io_error<T>(kind: ErrorKind, msg: T) -> io::Error
where
    T: Into<Box<dyn StdError + Send + Sync>>,
{
    io::Error::new(kind, msg)
}

impl From<Error> for io::Error {
    fn from(err: Error) -> io::Error {
        let kind = match err {
            Error::ConvInconsistent(..) => ErrorKind::Other,
            Error::InvalidMtu(..) => ErrorKind::Other,
            Error::InvalidSegmentSize(..) => ErrorKind::Other,
            Error::InvalidSegmentDataSize(..) => ErrorKind::Other,
            Error::IoError(err) => return err,
            Error::NeedUpdate => ErrorKind::Other,
            Error::RecvQueueEmpty => ErrorKind::WouldBlock,
            Error::ExpectingFragment => ErrorKind::WouldBlock,
            Error::UnsupportedCmd(..) => ErrorKind::Other,
            Error::UserBufTooBig => ErrorKind::Other,
            Error::UserBufTooSmall => ErrorKind::Other,
        };

        make_io_error(kind, err)
    }
}
