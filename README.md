# compio-rustls

Async TLS/SSL for [`compio`](https://crates.io/crates/compio) via
[`rustls`](https://crates.io/crates/rustls).

Rough example of how to use this crate can be found at the
[tests/](tests/) directory. If you are familiar `tokio-rustls`, then it
should be familiar to you.

TLS ciphertext buffers use [`bytes-rc`](https://crates.io/crates/bytes-rc)
with non-atomic reference counts. Keep each TLS stream and its I/O operations
on one Compio runtime thread. The stream types do not implement `Send` or
`Sync`.

## License

This project is licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) of
<http://www.apache.org/licenses/LICENSE-2.0>)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion by you, as defined in the Apache-2.0 license, shall be dual
licensed as above, without any additional terms or conditions.
