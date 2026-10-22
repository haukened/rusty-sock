# List recipes.
default:
    @just --list

# Everything CI checks, minus fuzzing.
check: fmt clippy cov deny

fmt:
    cargo fmt --all --check

clippy:
    cargo clippy --all-targets -- -D warnings

test:
    cargo test

# Tests with coverage; fails unless every library line is covered.
cov:
    scripts/coverage.sh

deny:
    cargo deny check

# Fuzz one parser (greeting, userpass, request, udp). Needs nightly.
fuzz target="request" secs="60":
    cargo +nightly fuzz run {{target}} -- -max_total_time={{secs}}

# Fully static binaries for x86_64 and aarch64 (needs cargo-zigbuild).
static:
    cargo zigbuild --release --target x86_64-unknown-linux-musl --target aarch64-unknown-linux-musl
    scripts/check-static.sh target/x86_64-unknown-linux-musl/release/rusty-sock target/aarch64-unknown-linux-musl/release/rusty-sock

# Scratch container image from the x86_64 static binary.
docker: static
    docker build -t rusty-sock .
