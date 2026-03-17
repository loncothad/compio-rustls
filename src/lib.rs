//! Async TLS/SSL for [`compio`](https://crates.io/crates/compio) via [`rustls`](https://crates.io/crates/rustls).

mod acceptor;
mod connector;
mod stream;
mod util;

pub(crate) const DEFAULT_BUF_CAPACITY: usize = 4096;

pub use ::rustls;
pub use stream::*;

pub mod client {
    pub use crate::connector::*;
}

pub mod server {
    pub use crate::acceptor::*;
}
