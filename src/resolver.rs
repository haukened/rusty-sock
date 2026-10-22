//! Destination resolution with the egress policy applied to resolved
//! addresses.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use hickory_resolver::TokioResolver;
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;

use crate::config::DnsConfig;
use crate::connector::BoxFuture;
use crate::error::ConnectError;
use crate::policy::EgressPolicy;
use crate::proto::TargetAddr;

/// Resolves hostnames to IP addresses. Abstracted for testing.
pub trait Resolve: Send + Sync {
    /// Look up the addresses of `host`.
    fn lookup<'a>(&'a self, host: &'a str) -> BoxFuture<'a, io::Result<Vec<IpAddr>>>;
}

/// A pure-Rust DNS stub resolver (no libc `getaddrinfo`).
#[derive(Debug, Clone)]
pub struct HickoryResolver {
    inner: TokioResolver,
}

impl HickoryResolver {
    /// Build a resolver from config: explicit nameservers, or the system
    /// configuration (`/etc/resolv.conf`) if none are given.
    ///
    /// # Errors
    /// If the system configuration cannot be read.
    pub fn new(config: &DnsConfig, timeout: Duration) -> io::Result<Self> {
        let mut builder = if config.nameservers.is_empty() {
            TokioResolver::builder_tokio().map_err(io::Error::other)?
        } else {
            let servers = config.nameservers.iter().map(|&a| name_server(a)).collect();
            TokioResolver::builder_with_config(
                ResolverConfig::from_name_servers(servers),
                TokioRuntimeProvider::default(),
            )
        };
        let opts = builder.options_mut();
        opts.timeout = timeout;
        opts.attempts = 2;
        let inner = builder.build().map_err(io::Error::other)?;
        Ok(Self { inner })
    }
}

fn name_server(addr: SocketAddr) -> NameServerConfig {
    let mut ns = NameServerConfig::udp_and_tcp(addr.ip());
    for conn in &mut ns.connections {
        conn.port = addr.port();
    }
    ns
}

impl Resolve for HickoryResolver {
    fn lookup<'a>(&'a self, host: &'a str) -> BoxFuture<'a, io::Result<Vec<IpAddr>>> {
        Box::pin(async move {
            // Treat every name as fully qualified so resolv.conf search
            // domains are never appended.
            let fqdn = format!("{}.", host.trim_end_matches('.'));
            let found = self.inner.lookup_ip(fqdn).await.map_err(io::Error::other)?;
            Ok(found.iter().collect())
        })
    }
}

/// Resolve `target` to the socket addresses permitted by `policy`.
///
/// IP literals (including ones sent as domain names) skip DNS. Every
/// resolved address is checked; disallowed ones are discarded so the caller
/// only ever connects to vetted addresses.
///
/// # Errors
/// [`ConnectError::Denied`] if no resolved address is allowed, or a
/// resolution error.
pub async fn resolve_target(
    resolver: &dyn Resolve,
    policy: &EgressPolicy,
    target: &TargetAddr,
    deadline: Duration,
) -> Result<Vec<SocketAddr>, ConnectError> {
    let addrs = match target {
        TargetAddr::Ip(addr) => vec![*addr],
        TargetAddr::Domain(host, port) => lookup(resolver, host, *port, deadline).await?,
    };
    let mut denied = None;
    let allowed: Vec<SocketAddr> = addrs
        .into_iter()
        .filter(|&a| policy.check(a).map_err(|e| denied = Some(e)).is_ok())
        .collect();
    match (allowed.is_empty(), denied) {
        (true, Some(reason)) => Err(ConnectError::Denied(reason)),
        (true, None) => Err(ConnectError::NoAddresses),
        (false, _) => Ok(allowed),
    }
}

async fn lookup(
    resolver: &dyn Resolve,
    host: &str,
    port: u16,
    deadline: Duration,
) -> Result<Vec<SocketAddr>, ConnectError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let ips = tokio::time::timeout(deadline, resolver.lookup(host))
        .await
        .map_err(|_| ConnectError::Timeout)?
        .map_err(ConnectError::Resolve)?;
    Ok(ips
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::policy::Denied;
    use std::collections::HashMap;

    /// A fixed name → addresses table.
    #[derive(Default)]
    pub(crate) struct StaticResolver(pub HashMap<String, Vec<IpAddr>>);

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

    struct Hang;
    impl Resolve for Hang {
        fn lookup<'a>(&'a self, _: &'a str) -> BoxFuture<'a, io::Result<Vec<IpAddr>>> {
            Box::pin(std::future::pending())
        }
    }

    const T: Duration = Duration::from_secs(1);

    fn resolver() -> StaticResolver {
        let mut map = HashMap::new();
        map.insert("public.test".into(), vec!["8.8.8.8".parse().unwrap()]);
        map.insert(
            "mixed.test".into(),
            vec!["10.0.0.1".parse().unwrap(), "1.1.1.1".parse().unwrap()],
        );
        map.insert("private.test".into(), vec!["127.0.0.1".parse().unwrap()]);
        map.insert("empty.test".into(), vec![]);
        StaticResolver(map)
    }

    async fn resolve(target: TargetAddr) -> Result<Vec<SocketAddr>, ConnectError> {
        resolve_target(&resolver(), &EgressPolicy::default(), &target, T).await
    }

    fn domain(name: &str) -> TargetAddr {
        TargetAddr::Domain(name.into(), 443)
    }

    #[tokio::test]
    async fn ip_targets_are_checked() {
        let ok = resolve(TargetAddr::Ip("8.8.8.8:53".parse().unwrap()))
            .await
            .unwrap();
        assert_eq!(ok, vec!["8.8.8.8:53".parse().unwrap()]);
        let err = resolve(TargetAddr::Ip("127.0.0.1:53".parse().unwrap())).await;
        assert!(matches!(err, Err(ConnectError::Denied(Denied::Address))));
    }

    #[tokio::test]
    async fn ip_literal_domains_skip_dns() {
        let err = resolve(domain("169.254.169.254")).await;
        assert!(matches!(err, Err(ConnectError::Denied(_))));
        assert_eq!(resolve(domain("1.1.1.1")).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn filters_resolved_addresses() {
        assert_eq!(resolve(domain("public.test")).await.unwrap().len(), 1);
        assert_eq!(
            resolve(domain("mixed.test")).await.unwrap(),
            vec!["1.1.1.1:443".parse().unwrap()]
        );
        assert!(matches!(
            resolve(domain("private.test")).await,
            Err(ConnectError::Denied(_))
        ));
        assert!(matches!(
            resolve(domain("empty.test")).await,
            Err(ConnectError::NoAddresses)
        ));
        assert!(matches!(
            resolve(domain("nx.test")).await,
            Err(ConnectError::Resolve(_))
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn lookup_times_out() {
        let err = resolve_target(&Hang, &EgressPolicy::default(), &domain("a"), T).await;
        assert!(matches!(err, Err(ConnectError::Timeout)));
    }

    #[test]
    fn name_server_uses_port() {
        let ns = name_server("127.0.0.1:5353".parse().unwrap());
        assert!(ns.connections.iter().all(|c| c.port == 5353));
    }
}
