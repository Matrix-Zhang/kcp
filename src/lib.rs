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
    pub use super::{Kcp, get_conv};
}

pub use error::Error;
pub use kcp::{Kcp, get_conv};

/// KCP result
pub type KcpResult<T> = Result<T, Error>;
