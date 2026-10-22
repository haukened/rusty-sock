//! Shared helpers for integration tests: a SOCKS5 client, mock upstream
//! servers and server construction.
#![allow(dead_code)]

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rusty_sock::auth::{CredentialStore, hash_password};
use rusty_sock::config::Limits;
use rusty_sock::connector::{BoxFuture, TcpConnector};
use rusty_sock::listener::Server;
use rusty_sock::policy::EgressPolicy;
use rusty_sock::resolver::Resolve;
use rusty_sock::session::{Authenticator, Ctx};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;

pub const USER: &str = "alice";
pub const PASS: &str = "wonderland";

/// Resolves names from a fixed table.
#[derive(Default, Clone)]
pub struct StaticResolver(pub HashMap<String, Vec<IpAddr>>);

impl StaticResolver {
    pub fn with(name: &str, ip: &str) -> Self {
        let mut map = HashMap::new();
        map.insert(name.to_owned(), vec![ip.parse().unwrap()]);
        Self(map)
    }
}

impl Resolve for StaticResolver {
    fn lookup<'a>(&'a self, host: &'a str) -> BoxFuture<'a, io::Result<Vec<IpAddr>>> {
        let res = self
            .0
            .get(host)
            .cloned()
            .ok_or_else(|| io::Error::other("NXDOMAIN"));
        Box::pin(async move { res })
    }
}

pub fn password_auth() -> Authenticator {
    let hash = hash_password(PASS.as_bytes()).unwrap();
    let store = CredentialStore::parse(&format!("{USER}:{hash}")).unwrap();
    Authenticator::Password(Arc::new(store))
}

/// A permissive context (private destinations allowed) for local tests.
pub fn ctx(auth: Authenticator) -> Ctx {
    Ctx {
        auth,
        policy: EgressPolicy {
            allow_private: true,
            ..Default::default()
        },
        resolver: Arc::new(StaticResolver::with("upstream.test", "127.0.0.1")),
        connector: Arc::new(TcpConnector),
        timeouts: Limits::default().timeouts(),
    }
}

/// A running server; dropping the handle stops it.
pub struct Running {
    pub addr: SocketAddr,
    _stop: oneshot::Sender<()>,
}

pub async fn start(ctx: Ctx, tls: Option<TlsAcceptor>, max_connections: usize) -> Running {
    let server = Server::bind("127.0.0.1:0".parse().unwrap(), ctx, tls, max_connections)
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    let (stop, stopped) = oneshot::channel::<()>();
    tokio::spawn(server.run(async move {
        let _ = stopped.await;
    }));
    Running { addr, _stop: stop }
}

/// Minimal SOCKS5 client.
pub struct Client<S> {
    pub stream: S,
}

impl Client<TcpStream> {
    pub async fn connect(server: SocketAddr) -> Self {
        Self {
            stream: TcpStream::connect(server).await.unwrap(),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Client<S> {
    /// Send a greeting and return the selected method.
    pub async fn greet(&mut self, methods: &[u8]) -> u8 {
        let mut msg = vec![5, u8::try_from(methods.len()).unwrap()];
        msg.extend_from_slice(methods);
        self.stream.write_all(&msg).await.unwrap();
        let mut resp = [0u8; 2];
        self.stream.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp[0], 5);
        resp[1]
    }

    /// RFC 1929 sub-negotiation; returns the status byte.
    pub async fn login(&mut self, user: &str, pass: &str) -> u8 {
        let mut msg = vec![1, u8::try_from(user.len()).unwrap()];
        msg.extend_from_slice(user.as_bytes());
        msg.push(u8::try_from(pass.len()).unwrap());
        msg.extend_from_slice(pass.as_bytes());
        self.stream.write_all(&msg).await.unwrap();
        let mut resp = [0u8; 2];
        self.stream.read_exact(&mut resp).await.unwrap();
        resp[1]
    }

    /// Greet with username/password and log in successfully.
    pub async fn authenticate(&mut self) {
        assert_eq!(self.greet(&[2]).await, 2);
        assert_eq!(self.login(USER, PASS).await, 0);
    }

    /// Send a request and return `(REP, BND)`.
    pub async fn request(&mut self, cmd: u8, target: &[u8]) -> (u8, SocketAddr) {
        let mut msg = vec![5, cmd, 0];
        msg.extend_from_slice(target);
        self.stream.write_all(&msg).await.unwrap();
        self.read_reply().await
    }

    pub async fn read_reply(&mut self) -> (u8, SocketAddr) {
        let mut head = [0u8; 4];
        self.stream.read_exact(&mut head).await.unwrap();
        assert_eq!(head[0], 5);
        let ip: IpAddr = match head[3] {
            1 => {
                let mut b = [0u8; 4];
                self.stream.read_exact(&mut b).await.unwrap();
                b.into()
            }
            4 => {
                let mut b = [0u8; 16];
                self.stream.read_exact(&mut b).await.unwrap();
                b.into()
            }
            other => panic!("unexpected ATYP {other}"),
        };
        let port = self.stream.read_u16().await.unwrap();
        (head[1], SocketAddr::new(ip, port))
    }
}

/// Encode a target address: `ATYP | ADDR | PORT`.
pub fn ip_target(addr: SocketAddr) -> Vec<u8> {
    let mut out = Vec::new();
    match addr.ip() {
        IpAddr::V4(ip) => {
            out.push(1);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(4);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
    out
}

pub fn domain_target(name: &str, port: u16) -> Vec<u8> {
    let mut out = vec![3, u8::try_from(name.len()).unwrap()];
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&port.to_be_bytes());
    out
}

pub const HTTP_BODY: &str = "hello from upstream";

/// A one-request-per-connection HTTP/1.1 server.
pub async fn http_server(bind: &str) -> SocketAddr {
    let listener = TcpListener::bind(bind).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 1024];
                let mut req = Vec::new();
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = sock.read(&mut buf).await.unwrap();
                    if n == 0 {
                        return;
                    }
                    req.extend_from_slice(&buf[..n]);
                }
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{HTTP_BODY}",
                    HTTP_BODY.len()
                );
                sock.write_all(resp.as_bytes()).await.unwrap();
            });
        }
    });
    addr
}

/// Send a GET and return the full response.
pub async fn http_get<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, host: &str) -> String {
    let req = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut out = String::new();
    stream.read_to_string(&mut out).await.unwrap();
    out
}

/// A self-signed `localhost` certificate: (cert PEM, key PEM).
pub fn self_signed() -> (String, String) {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    (cert.pem(), key.serialize_pem())
}

/// Write PEMs into a temp dir and return a [`rusty_sock::config::TlsConfig`].
pub fn write_tls_files(tag: &str, cert: &str, key: &str) -> rusty_sock::config::TlsConfig {
    let dir = std::env::temp_dir().join(format!("rusty-sock-it-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = rusty_sock::config::TlsConfig {
        cert: dir.join("cert.pem"),
        key: dir.join("key.pem"),
    };
    std::fs::write(&cfg.cert, cert).unwrap();
    std::fs::write(&cfg.key, key).unwrap();
    cfg
}

/// A TLS client connector that trusts exactly `cert_pem`.
pub fn tls_connector(cert_pem: &str) -> tokio_rustls::TlsConnector {
    use rustls_pki_types::CertificateDer;
    use rustls_pki_types::pem::PemObject;
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(cert_pem.as_bytes()).unwrap())
        .unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(config))
}

/// An HTTPS server (TLS + the same HTTP response).
pub async fn https_server(cert_pem: &str, key_pem: &str) -> SocketAddr {
    let cfg = write_tls_files("https-upstream", cert_pem, key_pem);
    let acceptor = rusty_sock::tls::acceptor(&cfg).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(sock).await else {
                    return;
                };
                let mut buf = vec![0u8; 1024];
                let _ = tls.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{HTTP_BODY}",
                    HTTP_BODY.len()
                );
                tls.write_all(resp.as_bytes()).await.unwrap();
                tls.shutdown().await.unwrap();
            });
        }
    });
    addr
}

/// A DNS server answering every A query with `answer`.
pub async fn dns_server(answer: [u8; 4]) -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 512];
        while let Ok((n, src)) = sock.recv_from(&mut buf).await {
            if let Some(resp) = dns_answer(&buf[..n], answer) {
                let _ = sock.send_to(&resp, src).await;
            }
        }
    });
    addr
}

/// Build a response with one A record (or an empty answer for non-A).
pub fn dns_answer(query: &[u8], answer: [u8; 4]) -> Option<Vec<u8>> {
    let question_end = 12 + query.get(12..)?.iter().position(|&b| b == 0)? + 1 + 4;
    let question = query.get(12..question_end)?;
    let qtype = u16::from_be_bytes([question[question.len() - 4], question[question.len() - 3]]);
    let is_a = qtype == 1;
    let mut out = Vec::new();
    out.extend_from_slice(&query[..2]); // ID
    out.extend_from_slice(&[0x81, 0x80]); // response, RD, RA, NOERROR
    out.extend_from_slice(&[0, 1, 0, u8::from(is_a), 0, 0, 0, 0]);
    out.extend_from_slice(question);
    if is_a {
        out.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        out.extend_from_slice(&answer);
    }
    Some(out)
}

/// Build a DNS query for an A record.
pub fn dns_query(id: u16, name: &str) -> Vec<u8> {
    let mut out = id.to_be_bytes().to_vec();
    out.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        out.push(u8::try_from(label.len()).unwrap());
        out.extend_from_slice(label.as_bytes());
    }
    out.extend_from_slice(&[0, 0, 1, 0, 1]);
    out
}

pub const SHORT: Duration = Duration::from_millis(300);
