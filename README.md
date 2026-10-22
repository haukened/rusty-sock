# rusty-sock

Yet another Rust implementation of a SOCKS5 proxy. This one is small, has secure defaults, and ships as a fully static binary.

- **CONNECT** (RFC 1928) carries HTTP, HTTPS, or any other TCP traffic.
- **Server-side DNS** resolves domain-name targets on the server (`socks5h://`). It uses a pure-Rust resolver (hickory) rather than libc.
- **UDP ASSOCIATE** relays raw UDP, e.g. DNS queries to port 53.
- **Username/password auth** (RFC 1929) checks passwords against Argon2id hashes.
- **Optional TLS listener** (rustls) keeps credentials off the wire in cleartext.
- **Egress policy** blocks loopback, private, link-local (cloud metadata) and other non-public destinations by default. It checks the addresses a name *resolves to*, so a DNS answer can't be used to sneak past it.
- **Static musl binaries** for x86_64 and aarch64, which can run `FROM scratch`.

## Quick start

```sh
cargo build --release

# Create a users file (one `user:$argon2id$...` line per user).
printf '%s\n' 'correct horse battery staple' \
  | ./target/release/rusty-sock hash-password \
  | sed 's/^/alice:/' > users
chmod 600 users

cp config.example.toml config.toml   # points at ./users
./target/release/rusty-sock serve --config config.toml

curl -x socks5h://alice:'correct horse battery staple'@127.0.0.1:1080 https://example.com
```

Logging is controlled with `RUST_LOG` (default `info`), e.g. `RUST_LOG=rusty_sock=debug`.

## Install from packages (systemd)

Release builds include `.deb` (Debian 12+, Ubuntu 22.04+) and `.rpm` (RHEL/Rocky/Alma 9+, Fedora) packages built from the static binary. They need systemd ≥ 247.

```sh
sudo apt install ./rusty-sock_*_amd64.deb      # or: sudo dnf install ./rusty-sock-*.x86_64.rpm

# Add a user (the users file is root-only, 0600):
echo "alice:$(printf '%s\n' 'the-password' | rusty-sock hash-password)" | sudo tee -a /etc/rusty-sock/users

sudo systemctl enable --now rusty-sock      # installed disabled; nothing runs until you do this
journalctl -u rusty-sock
```

| Path | Purpose |
|---|---|
| `/etc/rusty-sock/config.toml` | config (conffile, kept on upgrade) |
| `/etc/rusty-sock/users` | users, `root:root 0600` (conffile) |
| `/etc/rusty-sock/tls/{cert,key}.pem` | TLS material, if enabled |
| `/usr/lib/systemd/system/rusty-sock.service` | hardened unit |
| `/usr/share/doc/rusty-sock/dropins/` | optional drop-ins: `tls.conf`, `low-port.conf` |

Logs go to stdout. Under systemd they land in the journal, without colour codes or duplicate timestamps.

### How the service is sandboxed

- **No fixed account.** `DynamicUser=yes` runs the service as an ephemeral user that exists only while it runs, so the package creates no account.
- **Secrets stay root-only.** The users file (and the TLS key, if used) stays `root:root 0600`. systemd passes it in with `LoadCredential=`, which exposes a private copy under `$CREDENTIALS_DIRECTORY` to that run only.
- **No capabilities.** The bounding and ambient capability sets are empty, and `NoNewPrivileges=yes` is set.
- **Filesystem and kernel locked down.** The service gets a read-only OS, private `/tmp`, no devices, protected kernel tunables, modules, logs and clock, and its own user namespace.
- **Restricted system calls.** Only IPv4/IPv6 sockets are allowed, with a `@system-service` syscall filter that also excludes `@privileged` and `@resources`. `MemoryDenyWriteExecute=yes` blocks writable-executable memory, and `LockPersonality=yes` stops the process changing its execution domain.
- **Exposure score.** `systemd-analyze security rusty-sock` reports **1.1 (OK)**, and CI fails if it rises above 2.0. The only remaining items are inherent to a network proxy (it needs internet sockets and the host network).

**Enabling TLS.** Put the certificate and key in `/etc/rusty-sock/tls/` (both `0600`). Copy `/usr/share/doc/rusty-sock/dropins/tls.conf` to `/etc/systemd/system/rusty-sock.service.d/`, add an empty `[tls]` section to the config, then run `systemctl daemon-reload` and `systemctl restart rusty-sock`.

**Listening below port 1024.** Install the `low-port.conf` drop-in. It grants `CAP_NET_BIND_SERVICE` and nothing else.

## Configuration

`rusty-sock serve` reads `/etc/rusty-sock/config.toml` unless `-c/--config PATH` is given.

Secret files are found in this order:
1. a path set explicitly in the config;
2. a systemd credential (`$CREDENTIALS_DIRECTORY/users`, `tls-cert` or `tls-key`);
3. the default under `/etc/rusty-sock/`.

See [`config.example.toml`](config.example.toml) for every option. Unknown keys are rejected. Relative paths are resolved against the config file's directory.

| Section | Key | Default | Notes |
|---|---|---|---|
| | `listen` | `127.0.0.1:1080` | |
| `[auth]` | `mode` | `password` | `password` or `none` |
| | `users_file` | `/etc/rusty-sock/users` | or the `users` credential |
| | `allow_open_proxy` | `false` | needed for `mode = "none"` on a non-loopback address |
| `[tls]` | `cert`, `key` | `/etc/rusty-sock/tls/{cert,key}.pem` | section presence enables SOCKS over TLS; or `tls-cert`/`tls-key` credentials |
| `[limits]` | `max_connections` | `1024` | extra connections are dropped |
| | `handshake_timeout_secs` | `10` | TLS + negotiation + auth + request |
| | `connect_timeout_secs` | `10` | |
| | `idle_timeout_secs` | `300` | TCP relay inactivity |
| | `dns_timeout_secs` | `5` | |
| | `udp_idle_timeout_secs` | `120` | |
| `[egress]` | `allow_private` | `false` | allow non-public destinations |
| | `allowed_ports` | `[]` (all) | destination port allowlist |
| `[dns]` | `nameservers` | `[]` | e.g. `["1.1.1.1:53"]`; empty uses `/etc/resolv.conf` |

## Security notes

- **Cleartext credentials.** RFC 1929 sends the password in the clear. Bind to loopback, put the proxy behind a VPN, or enable `[tls]`. The server warns when password auth runs over plaintext on a non-loopback address. Most stock SOCKS clients can't speak TLS. Use a client that can, or a local TLS tunnel such as `stunnel`.
- **UDP relay is never encrypted.** Even with TLS on, UDP ASSOCIATE datagrams travel in the clear, because DTLS is not implemented.
- **UDP source checks.** The relay accepts datagrams only from the client's IP. It locks onto the declared source port, or onto the port of the first datagram if none was declared. It forwards replies only from destinations the client has contacted.
- **Credential checks.** Password checks take the same time whether or not the username exists. Unknown users are verified against a dummy hash.
- **Users-file permissions.** Keep the users file `chmod 600`. The server warns if it is readable by group or others.

### Deviations from RFC 1928

| Feature | Status |
|---|---|
| GSSAPI (method 0x01) | **Not implemented.** The RFC marks it MUST; clients that require it get `0xFF` (no acceptable methods). |
| BIND | Replies `0x07` (command not supported). |
| UDP fragmentation | Fragmented datagrams (FRAG ≠ 0) are dropped, as the RFC allows. |

## Static binaries and containers

The dependency tree is pure Rust apart from `ring`'s small C/assembly core. `deny.toml` bans OpenSSL, aws-lc and system GSSAPI, so a C dependency can't creep in.

```sh
# x86_64 only: needs musl-tools (apt install musl-tools)
cargo build --release --target x86_64-unknown-linux-musl

# x86_64 + aarch64: needs cargo-zigbuild (pip install cargo-zigbuild ziglang)
just static            # builds both and verifies they are statically linked

docker build -t rusty-sock .
docker run --rm -p 1080:1080 \
  -v "$PWD/config.toml:/etc/rusty-sock/config.toml:ro" \
  -v "$PWD/users:/etc/rusty-sock/users:ro" \
  rusty-sock
```

In a container, set `listen = "0.0.0.0:1080"`. If the image has no `/etc/resolv.conf`, also set `[dns] nameservers`.

Performance note: musl's allocator is slower than glibc's under heavy concurrency. Benchmark before deploying at high load; swapping in a different global allocator is a planned option.

## Development

| Command | What it does |
|---|---|
| `just check` | fmt, clippy (`-D warnings`, pedantic), tests with coverage, cargo-deny |
| `just cov` | `scripts/coverage.sh`: fails unless 100% of library lines are covered |
| `just fuzz request 60` | fuzz a parser (`greeting`, `userpass`, `request`, `udp`); needs nightly |
| `just static` | static musl builds + linkage check |
| `just packages` | `.deb` + `.rpm` from the static x86_64 binary |
| `just package-smoke` | install/remove the packages in Debian, Ubuntu, Rocky and Fedora containers |
| `just package-e2e` | **sudo**: install the `.deb` on this machine, run the hardened service, verify the sandbox, purge |

### Code layout

- **Wire format:** `src/proto/` parses and encodes the SOCKS5 messages as pure functions, with no I/O. They are unit-tested, property-tested and fuzzed.
- **Session:** `src/session.rs` runs each connection: negotiate, authenticate, read the request, then dispatch. It is generic over the stream, so tests run it over in-memory pipes and production runs it over TCP or TLS.
- **Relays:** `src/relay/` holds the TCP relay (`tcp.rs`, with an idle timeout) and the UDP relay (`udp.rs`).
- **Policy and resolution:** `src/policy.rs`, `src/resolver.rs` and `src/connector.rs` decide where traffic may go and how outbound connections are made.
- **Listener and TLS:** `src/listener.rs` and `src/tls.rs` handle accepting connections.
- **Integration tests:** `tests/` exercises HTTP, HTTPS, DNS over UDP ASSOCIATE, auth, TLS, limits and the config-driven entry point over real sockets.

### CI

`.github/workflows/ci.yml` runs these jobs:
- fmt
- clippy
- tests with coverage, uploaded to Codacy using the `CODACY_TOKEN` repository secret
- tests and a static build on musl
- an MSRV check (1.88)
- cargo-deny
- cargo-audit
- a 60-second fuzz smoke run per parser
- packaging: build the `.deb`/`.rpm`, gate the unit's exposure score, run install/remove tests in five distro containers, and run the systemd end-to-end test (`scripts/package-e2e.sh`) on the runner

`release.yml` runs on `v*` tags. It builds static x86_64 and aarch64 binaries plus `.deb` and `.rpm` packages for both, checks linkage, smoke-tests the scratch image, and publishes everything with SHA-256 sums.

## License

AGPL-3.0-only. See [LICENSE](LICENSE).
