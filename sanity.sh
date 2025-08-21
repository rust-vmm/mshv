cargo fmt -- --check
cross +stable build --release --target aarch64-unknown-linux-musl
cargo +stable build --release --target x86_64-unknown-linux-gnu
cargo clippy --all-targets --all-features -- -D warnings
