//! Egress policy: which destinations the proxy may connect to.
//!
//! By default only globally routable unicast addresses are allowed, which
//! prevents the proxy from being used to reach loopback, private networks or
//! cloud metadata endpoints (SSRF). The policy is applied to *resolved*
//! addresses, so a hostile DNS answer cannot bypass it.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use ipnet::{Ipv4Net, Ipv6Net};

const fn v4(a: u8, b: u8, c: u8, d: u8, len: u8) -> Ipv4Net {
    Ipv4Net::new_assert(Ipv4Addr::new(a, b, c, d), len)
}

const fn v6(s: [u16; 8], len: u8) -> Ipv6Net {
    Ipv6Net::new_assert(
        Ipv6Addr::new(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]),
        len,
    )
}

/// IPv4 ranges that are not globally reachable unicast.
const DENIED_V4: [Ipv4Net; 15] = [
    v4(0, 0, 0, 0, 8),       // "this network"
    v4(10, 0, 0, 0, 8),      // private
    v4(100, 64, 0, 0, 10),   // CGNAT
    v4(127, 0, 0, 0, 8),     // loopback
    v4(169, 254, 0, 0, 16),  // link-local (incl. cloud metadata)
    v4(172, 16, 0, 0, 12),   // private
    v4(192, 0, 0, 0, 24),    // IETF protocol assignments
    v4(192, 0, 2, 0, 24),    // TEST-NET-1
    v4(192, 88, 99, 0, 24),  // 6to4 relay anycast
    v4(192, 168, 0, 0, 16),  // private
    v4(198, 18, 0, 0, 15),   // benchmarking
    v4(198, 51, 100, 0, 24), // TEST-NET-2
    v4(203, 0, 113, 0, 24),  // TEST-NET-3
    v4(224, 0, 0, 0, 4),     // multicast
    v4(240, 0, 0, 0, 4),     // reserved + broadcast
];

/// IPv6 ranges that are not globally reachable unicast.
const DENIED_V6: [Ipv6Net; 8] = [
    v6([0, 0, 0, 0, 0, 0, 0, 0], 128),         // unspecified
    v6([0, 0, 0, 0, 0, 0, 0, 1], 128),         // loopback
    v6([0x100, 0, 0, 0, 0, 0, 0, 0], 64),      // discard-only
    v6([0x2001, 0, 0, 0, 0, 0, 0, 0], 23),     // IETF protocol assignments
    v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 32), // documentation
    v6([0xfc00, 0, 0, 0, 0, 0, 0, 0], 7),      // unique local
    v6([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10),     // link-local
    v6([0xff00, 0, 0, 0, 0, 0, 0, 0], 8),      // multicast
];

/// NAT64 well-known prefix; the embedded IPv4 address is checked instead.
const NAT64: Ipv6Net = v6([0x64, 0xff9b, 0, 0, 0, 0, 0, 0], 96);

/// Why a destination was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Denied {
    /// The address is in a non-public range.
    #[error("destination address is not publicly routable")]
    Address,
    /// The port is not in the allowlist.
    #[error("destination port is not allowed")]
    Port,
}

/// Destination filter applied to every outbound connection and datagram.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EgressPolicy {
    /// Allow non-public (private, loopback, link-local, ...) destinations.
    pub allow_private: bool,
    /// If non-empty, only these destination ports are allowed.
    pub allowed_ports: Vec<u16>,
}

impl EgressPolicy {
    /// Check whether `addr` may be contacted.
    ///
    /// # Errors
    /// Returns the reason the destination is refused.
    pub fn check(&self, addr: SocketAddr) -> Result<(), Denied> {
        if !self.allowed_ports.is_empty() && !self.allowed_ports.contains(&addr.port()) {
            return Err(Denied::Port);
        }
        if !self.allow_private && !is_public(addr.ip()) {
            return Err(Denied::Address);
        }
        Ok(())
    }
}

/// Whether `ip` is a globally routable unicast address.
#[must_use]
pub fn is_public(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(ip) => !DENIED_V4.iter().any(|net| net.contains(&ip)),
        IpAddr::V6(ip) => is_public_v6(ip),
    }
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    if NAT64.contains(&ip) {
        let [.., a, b, c, d] = ip.octets();
        return is_public(IpAddr::V4(Ipv4Addr::new(a, b, c, d)));
    }
    !DENIED_V6.iter().any(|net| net.contains(&ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn const_constructors() {
        assert_eq!(v4(10, 0, 0, 0, 8), "10.0.0.0/8".parse::<Ipv4Net>().unwrap());
        assert_eq!(
            v6([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10),
            "fe80::/10".parse::<Ipv6Net>().unwrap()
        );
    }

    #[test]
    fn denies_every_special_v4_range() {
        for net in DENIED_V4 {
            assert!(!is_public(IpAddr::V4(net.network())), "{net}");
            assert!(!is_public(IpAddr::V4(net.broadcast())), "{net}");
        }
    }

    #[test]
    fn denies_every_special_v6_range() {
        for net in DENIED_V6 {
            assert!(!is_public(IpAddr::V6(net.network())), "{net}");
        }
    }

    #[test]
    fn allows_public_addresses() {
        for s in [
            "1.1.1.1",
            "93.184.216.34",
            "2606:4700::1111",
            "64:ff9b::808:808",
        ] {
            assert!(is_public(ip(s)), "{s}");
        }
    }

    #[test]
    fn checks_embedded_ipv4() {
        assert!(!is_public(ip("::ffff:127.0.0.1")));
        assert!(!is_public(ip("::ffff:169.254.169.254")));
        assert!(!is_public(ip("64:ff9b::a00:1")));
        assert!(is_public(ip("::ffff:8.8.8.8")));
    }

    #[test]
    fn default_policy() {
        let p = EgressPolicy::default();
        assert_eq!(p.check("8.8.8.8:53".parse().unwrap()), Ok(()));
        assert_eq!(
            p.check("127.0.0.1:80".parse().unwrap()),
            Err(Denied::Address)
        );
    }

    #[test]
    fn allow_private() {
        let p = EgressPolicy {
            allow_private: true,
            ..Default::default()
        };
        assert_eq!(p.check("127.0.0.1:80".parse().unwrap()), Ok(()));
    }

    #[test]
    fn port_allowlist() {
        let p = EgressPolicy {
            allow_private: false,
            allowed_ports: vec![80, 443],
        };
        assert_eq!(p.check("8.8.8.8:443".parse().unwrap()), Ok(()));
        assert_eq!(p.check("8.8.8.8:25".parse().unwrap()), Err(Denied::Port));
    }
}
