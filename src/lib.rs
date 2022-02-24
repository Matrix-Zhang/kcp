//! [KCP](https://github.com/skywind3000/kcp) implementation in Rust.
//!
//! A Fast and Reliable ARQ Protocol

extern crate bytes;
#[macro_use]
extern crate log;

mod error;
mod kcp;

/// The `KCP` prelude
pub mod prelude {
    pub use super::{get_conv, Kcp};
}

pub use error::Error;
pub use kcp::{get_conv, get_sn, set_conv, Kcp};

/// KCP result
pub type KcpResult<T> = Result<T, Error>;
