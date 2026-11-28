//! Trusted client IP extraction (CIDR-guarded) and lightweight Core anomaly detection.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::http::HeaderMap;
use vaelspire_core::Id;
use vaelspire_core::privacy::truncate_ip;

/// Header source used to determine the real client IP when behind a trusted proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum IpSource {
    /// Always use the direct TCP peer address; ignore all forwarding headers.
    #[default]
    Direct,
    /// Use the first IP in `X-Forwarded-For` when the peer is a trusted proxy.
    XForwardedFor,
    /// Use `CF-Connecting-IP` (Cloudflare) when the peer is a trusted proxy.
    CfConnectingIp,
    /// Use RFC 7239 `Forwarded: for=...` when the peer is a trusted proxy.
    Forwarded,
}

impl IpSource {
    /// Stable lowercase identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::XForwardedFor => "x-forwarded-for",
            Self::CfConnectingIp => "cf-connecting-ip",
            Self::Forwarded => "forwarded",
        }
    }
}

/// IPv4 or IPv6 CIDR network block used to verify whether a peer is a trusted proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpCidr {
    /// IPv4 network prefix (`0..=32`).
    V4 {
        /// Masked network address.
        network: u32,
        /// Bitmask (`u32::MAX << (32 - prefix)` or `0` for `/0`).
        mask: u32,
    },
    /// IPv6 network prefix (`0..=128`).
    V6 {
        /// Masked network address.
        network: u128,
        /// Bitmask.
        mask: u128,
    },
}

impl IpCidr {
    /// Parse a CIDR string such as `10.0.0.0/8`, `127.0.0.1/32`, `::1/128`, or a bare IP.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let trimmed = raw.trim();
        if let Some((ip_part, prefix_part)) = trimmed.split_once('/') {
            let ip: IpAddr = ip_part.trim().parse().ok()?;
            let prefix: u32 = prefix_part.trim().parse().ok()?;
            match ip {
                IpAddr::V4(v4) if prefix <= 32 => {
                    let mask = if prefix == 0 {
                        0
                    } else {
                        u32::MAX.checked_shl(32 - prefix).unwrap_or(0)
                    };
                    Some(Self::V4 {
                        network: u32::from(v4) & mask,
                        mask,
                    })
                }
                IpAddr::V6(v6) if prefix <= 128 => {
                    let mask = if prefix == 0 {
                        0
                    } else {
                        u128::MAX.checked_shl(128 - prefix).unwrap_or(0)
                    };
                    Some(Self::V6 {
                        network: u128::from(v6) & mask,
                        mask,
                    })
                }
                _ => None,
            }
        } else {
            let ip: IpAddr = trimmed.parse().ok()?;
            match ip {
                IpAddr::V4(v4) => Some(Self::V4 {
                    network: u32::from(v4),
                    mask: u32::MAX,
                }),
                IpAddr::V6(v6) => Some(Self::V6 {
                    network: u128::from(v6),
                    mask: u128::MAX,
                }),
            }
        }
    }

    /// Check whether `ip` falls inside this CIDR block.
    #[must_use]
    pub fn contains(self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Self::V4 { network, mask }, IpAddr::V4(v4)) => (u32::from(v4) & mask) == network,
            (Self::V6 { network, mask }, IpAddr::V6(v6)) => (u128::from(v6) & mask) == network,
            _ => false,
        }
    }
}

/// Extract the effective client IP according to [`IpSource`] and trusted proxy CIDRs.
///
/// If `trusted_proxies` is non-empty, forwarding headers are ONLY honored when `peer_ip`
/// matches at least one CIDR block; otherwise `peer_ip` is returned unchanged.
#[must_use]
pub fn extract_client_ip(
    peer_ip: Option<IpAddr>,
    headers: &HeaderMap,
    source: IpSource,
    trusted_proxies: &[IpCidr],
) -> Option<IpAddr> {
    if source == IpSource::Direct {
        return peer_ip;
    }
    if !trusted_proxies.is_empty() {
        let peer = peer_ip?;
        if !trusted_proxies.iter().any(|cidr| cidr.contains(peer)) {
            return Some(peer);
        }
    }

    let forwarded = match source {
        IpSource::Direct => None,
        IpSource::XForwardedFor => headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .and_then(|first| first.trim().parse::<IpAddr>().ok()),
        IpSource::CfConnectingIp => headers
            .get("cf-connecting-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<IpAddr>().ok()),
        IpSource::Forwarded => parse_rfc7239_forwarded(headers),
    };

    forwarded.or(peer_ip)
}

fn parse_rfc7239_forwarded(headers: &HeaderMap) -> Option<IpAddr> {
    let raw = headers.get("forwarded")?.to_str().ok()?;
    for entry in raw.split(',') {
        for pair in entry.split(';') {
            let trimmed = pair.trim();
            if let Some(val) = trimmed
                .strip_prefix("for=")
                .or_else(|| trimmed.strip_prefix("FOR="))
            {
                let unquoted = val.trim().trim_matches('"');
                // Strip optional IPv6 brackets and port (e.g. "[2001:db8::1]:443" or "203.0.113.1:1234").
                let host = if let Some(inner) = unquoted.strip_prefix('[') {
                    inner.split(']').next().unwrap_or(unquoted)
                } else if unquoted.matches(':').count() == 1 {
                    unquoted.split(':').next().unwrap_or(unquoted)
                } else {
                    unquoted
                };
                if let Ok(ip) = host.parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }
    }
    None
}

/// Classification of a detected authentication anomaly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnomalyKind {
    /// A single source IP failed authentication across many distinct accounts in a short window.
    PasswordSpray,
    /// A user signed in from a previously unseen subnet + user-agent fingerprint.
    NewDeviceOrIp,
    /// An already-rotated OIDC refresh token was replayed (family revoked).
    RefreshTokenReuse,
}

impl AnomalyKind {
    /// Stable low-cardinality Prometheus / log label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PasswordSpray => "password_spray",
            Self::NewDeviceOrIp => "new_device_or_ip",
            Self::RefreshTokenReuse => "refresh_token_reuse",
        }
    }
}

/// Bounded in-memory anomaly detector for Core single-region deployments.
#[derive(Debug)]
pub struct AnomalyDetector {
    spray_window: Duration,
    spray_distinct_threshold: usize,
    inner: Mutex<DetectorState>,
}

#[derive(Debug, Default)]
struct DetectorState {
    /// Map of `source_ip -> deque<(Instant, account_fingerprint)>`.
    failures_by_ip: HashMap<String, VecDeque<(Instant, u64)>>,
    /// Map of `user_id -> known (subnet, ua_hash)` pairs.
    known_devices: HashMap<Id, HashSet<(String, u64)>>,
}

impl Default for AnomalyDetector {
    fn default() -> Self {
        Self::new(Duration::from_secs(300), 5)
    }
}

impl AnomalyDetector {
    /// Create a detector that flags password spray after `spray_distinct_threshold` distinct
    /// accounts fail from one IP within `spray_window`.
    #[must_use]
    pub fn new(spray_window: Duration, spray_distinct_threshold: usize) -> Self {
        Self {
            spray_window,
            spray_distinct_threshold: spray_distinct_threshold.max(2),
            inner: Mutex::new(DetectorState::default()),
        }
    }

    /// Record a failed authentication attempt from `ip` targeting `account_key`.
    ///
    /// Returns `Some(AnomalyKind::PasswordSpray)` when the IP has hit distinct accounts
    /// at or above the configured threshold within the sliding window.
    #[must_use]
    pub fn record_failure(&self, ip: &str, account_key: &str) -> Option<AnomalyKind> {
        let now = Instant::now();
        let fp = fnv1a_64(account_key.as_bytes());
        let mut guard = self.inner.lock().ok()?;
        if guard.failures_by_ip.len() > 10_000 {
            guard.failures_by_ip.clear();
        }
        let entries = guard.failures_by_ip.entry(ip.to_owned()).or_default();
        while let Some((ts, _)) = entries.front() {
            if now.saturating_duration_since(*ts) > self.spray_window {
                entries.pop_front();
            } else {
                break;
            }
        }
        entries.push_back((now, fp));
        let distinct: HashSet<u64> = entries.iter().map(|(_, f)| *f).collect();
        (distinct.len() >= self.spray_distinct_threshold).then_some(AnomalyKind::PasswordSpray)
    }

    /// Record a successful sign-in for `user_id` from `ip` and `user_agent`.
    ///
    /// Returns `Some(AnomalyKind::NewDeviceOrIp)` if the user had prior known devices
    /// and this `(subnet, ua)` pair has never been seen before.
    #[must_use]
    pub fn record_success(
        &self,
        user_id: Id,
        ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Option<AnomalyKind> {
        let subnet = ip.map_or_else(|| "unknown".to_owned(), truncate_ip);
        let ua_hash = fnv1a_64(user_agent.unwrap_or("").as_bytes());
        let mut guard = self.inner.lock().ok()?;
        if guard.known_devices.len() > 50_000 {
            guard.known_devices.clear();
        }
        let known = guard.known_devices.entry(user_id).or_default();
        let had_history = !known.is_empty();
        let is_new = known.insert((subnet, ua_hash));
        (had_history && is_new).then_some(AnomalyKind::NewDeviceOrIp)
    }
}

fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

/// Convenience helper for local IPv4/IPv6 loopback CIDR checks.
#[must_use]
pub fn default_loopback_cidrs() -> Vec<IpCidr> {
    vec![
        IpCidr::V4 {
            network: u32::from(Ipv4Addr::new(127, 0, 0, 0)),
            mask: 0xff00_0000,
        },
        IpCidr::V6 {
            network: u128::from(Ipv6Addr::LOCALHOST),
            mask: u128::MAX,
        },
    ]
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    #[test]
    fn cidr_guards_proxy_header_trust() {
        let trusted = vec![IpCidr::parse("10.0.0.0/8").expect("cidr")];
        let mut headers = HeaderMap::new();
        headers.insert("cf-connecting-ip", HeaderValue::from_static("198.51.100.7"));

        // Trusted proxy -> honors CF-Connecting-IP
        let ok = extract_client_ip(
            Some("10.1.2.3".parse().unwrap()),
            &headers,
            IpSource::CfConnectingIp,
            &trusted,
        );
        assert_eq!(ok, Some("198.51.100.7".parse().unwrap()));

        // Untrusted peer -> ignores spoofed CF-Connecting-IP and keeps peer IP
        let spoof = extract_client_ip(
            Some("203.0.113.99".parse().unwrap()),
            &headers,
            IpSource::CfConnectingIp,
            &trusted,
        );
        assert_eq!(spoof, Some("203.0.113.99".parse().unwrap()));
    }

    #[test]
    fn detects_password_spray_and_new_device() {
        let det = AnomalyDetector::new(Duration::from_secs(60), 3);
        assert_eq!(det.record_failure("203.0.113.5", "a@example.com"), None);
        assert_eq!(det.record_failure("203.0.113.5", "b@example.com"), None);
        assert_eq!(
            det.record_failure("203.0.113.5", "c@example.com"),
            Some(AnomalyKind::PasswordSpray)
        );

        let user = Id::now_v7();
        assert_eq!(
            det.record_success(user, Some("198.51.100.10"), Some("Mozilla/5.0")),
            None
        );
        assert_eq!(
            det.record_success(user, Some("198.51.100.22"), Some("Mozilla/5.0")),
            None,
            "same /24 subnet + UA is known"
        );
        assert_eq!(
            det.record_success(user, Some("203.0.113.50"), Some("curl/8.0")),
            Some(AnomalyKind::NewDeviceOrIp)
        );
    }
}
