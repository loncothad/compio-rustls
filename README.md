# compio-rustls

Async TLS/SSL for [`compio`](https://crates.io/crates/compio) via
[`rustls`](https://crates.io/crates/rustls).

Rough example of how to use this crate can be found at the
[tests/](tests/) directory. If you are familiar `tokio-rustls`, then it
should be familiar to you.

## Rust version and development

The minimum supported Rust version (MSRV) is **1.100**, with the 2024 edition.
Rust 1.100 stabilizes the core Allocator API. This crate has no direct raw
allocation calls to migrate and does not add custom-allocator public APIs.

This baseline targets the stable Rust 1.100 release and was validated locally
with Rust 1.100 beta while the release was still pending. No beta toolchain
is enforced by this repository.

Use `cargo check`, `cargo clippy --workspace --all-targets --all-features`,
and `cargo test --workspace --all-features` with Rust 1.100 or newer.
`just check` also uses ordinary Cargo. TLS integration tests need a supported
compio I/O backend.

`.rustfmt.toml` enables nightly-only formatting options. For formatting,
select nightly explicitly, for example with `RUSTUP_TOOLCHAIN=nightly just fmt`.
Builds, checks, and tests do not require nightly.

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
