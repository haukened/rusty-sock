# Minimal image: just the static binary. Build the binary first:
#   just static   (or cargo build --release --target x86_64-unknown-linux-musl)
FROM scratch
ARG BINARY=target/x86_64-unknown-linux-musl/release/rusty-sock
COPY ${BINARY} /rusty-sock
USER 65534:65534
EXPOSE 1080
ENTRYPOINT ["/rusty-sock"]
CMD ["serve", "--config", "/etc/rusty-sock/config.toml"]
