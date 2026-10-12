//! Async TLS/SSL for [`compio`](https://crates.io/crates/compio) via [`rustls`](https://crates.io/crates/rustls).
//!
//! TLS buffers use `bytes-rc` for non-atomic reference counting. Keep streams
//! and their I/O operations on one runtime thread; the buffers are not `Send`
//! or `Sync`.
//!
//! ```compile_fail
//! fn require_send<T: Send>() {}
//! require_send::<compio_rustls::TlsStream<(), ()>>();
//! ```
//!
//! ```compile_fail
//! fn require_sync<T: Sync>() {}
//! require_sync::<compio_rustls::TlsStream<(), ()>>();
//! ```

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
