This crate compiles the production I/O adapter and its tests directly. It omits
TLS provider FFI so Miri can check buffer initialization, pointer provenance,
shared views, and allocation reuse.

From the repository root:

```sh
rustup toolchain install nightly --profile minimal --component miri,rust-src
MIRIFLAGS=-Zmiri-strict-provenance cargo +nightly miri test --locked --manifest-path validation/io-buffer/Cargo.toml
MIRIFLAGS='-Zmiri-strict-provenance -Zmiri-tree-borrows' cargo +nightly miri test --locked --manifest-path validation/io-buffer/Cargo.toml
```

Keep the dependency versions in this manifest aligned with the main lockfile.
