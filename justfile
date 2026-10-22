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

# .deb and .rpm from the x86_64 static binary (needs cargo-zigbuild,
# cargo-deb and cargo-generate-rpm).
packages:
    cargo zigbuild --release --target x86_64-unknown-linux-musl
    cargo deb --no-build --no-strip --target x86_64-unknown-linux-musl
    cargo generate-rpm --target x86_64-unknown-linux-musl

# Install/remove the packages in distro containers (needs docker).
package-smoke: packages
    for img in debian:12 ubuntu:22.04 ubuntu:24.04; do docker run --rm -v "$PWD/$(ls target/x86_64-unknown-linux-musl/debian/*.deb):/pkg/r.deb:ro" -v "$PWD/scripts:/s:ro" "$img" /s/package-smoke.sh /pkg/r.deb; done
    for img in rockylinux:9 fedora:latest; do docker run --rm -v "$PWD/$(ls target/x86_64-unknown-linux-musl/generate-rpm/*.rpm):/pkg/r.rpm:ro" -v "$PWD/scripts:/s:ro" "$img" /s/package-smoke.sh /pkg/r.rpm; done

# Full systemd test on this machine: installs and purges the .deb (sudo).
package-e2e: packages
    sudo scripts/package-e2e.sh target/x86_64-unknown-linux-musl/debian/*.deb
