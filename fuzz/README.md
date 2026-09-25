# Bcrypt Fuzzing

This target fuzzes the x86-64 bcrypt v1 and v2 decoders with malformed hashes and request headers.

Install the nightly Rust toolchain and `cargo-fuzz`, then run from the repository root:

```bash
rustup run nightly cargo fuzz run bcrypt-parser
```

For a non-instrumented smoke run on stable Rust, use `cargo run --manifest-path fuzz/Cargo.toml --bin bcrypt-parser -- -runs=100`.

The target intentionally uses valid backing buffers for all pointers. Arbitrary invalid addresses are outside the raw assembly ABI contract.
