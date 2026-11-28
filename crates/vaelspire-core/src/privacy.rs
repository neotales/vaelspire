//! Privacy, GDPR redaction, and PII-safe logging primitives.
//!
//! Never log raw email addresses, passwords, session tokens, or API keys in
//! production logs. Pair a pseudonymous [`Id`] (`UUIDv7`) with [`format_email_for_log`]
//! (producing `wf******@domain.com` by default) and use [`truncate_ip`] for
//! GDPR-compliant IP subnet retention.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::Id;

/// Controls how email addresses are rendered in operational logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PiiLogMode {
    /// Show the first 1–2 characters of the local part, mask the rest with `*`,
    /// and preserve the domain (e.g., `wf******@domain.com`). Safe default.
    #[default]
    Masked,
    /// Never emit any part of the email address; log `[redacted]` and rely on `user_id`.
    IdOnly,
    /// Emit full email addresses (intended strictly for local development debugging).
    Full,
}

impl PiiLogMode {
    /// Stable lowercase identifier for configuration and discovery output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Masked => "masked",
            Self::IdOnly => "id-only",
            Self::Full => "full",
        }
    }

    /// Parse a lowercase configuration string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "masked" => Some(Self::Masked),
            "id-only" => Some(Self::IdOnly),
            "full" => Some(Self::Full),
            _ => None,
        }
    }
}

/// Controls how client IP addresses are written into append-only audit logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuditIpMode {
    /// Store the full trusted client IP address (default; needed for short-term forensics).
    #[default]
    Full,
    /// Store only the anonymized subnet (`/24` for IPv4, `/48` for IPv6) from birth.
    Truncated,
    /// Omit IP addresses from audit rows completely (strictest GDPR minimization).
    None,
}

impl AuditIpMode {
    /// Stable lowercase identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Truncated => "truncated",
            Self::None => "none",
        }
    }

    /// Parse a lowercase configuration string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "full" => Some(Self::Full),
            "truncated" => Some(Self::Truncated),
            "none" => Some(Self::None),
            _ => None,
        }
    }
}

/// Redact an email address for GDPR-safe logs, keeping only leading characters and domain.
///
/// Examples:
/// - `wfischer@domain.com` -> `wf******@domain.com`
/// - `alice@example.org` -> `al***@example.org`
/// - `bob@example.org` -> `b**@example.org`
/// - `a@example.org` -> `*@example.org`
#[must_use]
pub fn redact_email(email: &str) -> String {
    let trimmed = email.trim();
    let Some((local, domain)) = trimmed.split_once('@') else {
        return "[redacted]".to_owned();
    };
    let chars: Vec<char> = local.chars().collect();
    let visible = match chars.len() {
        0 => return format!("*@{domain}"),
        1 => 0,
        2 | 3 => 1,
        _ => 2,
    };
    let mut out = String::with_capacity(trimmed.len());
    for &ch in &chars[..visible] {
        out.push(ch);
    }
    let masked_count = (chars.len() - visible).max(1);
    for _ in 0..masked_count {
        out.push('*');
    }
    out.push('@');
    out.push_str(domain);
    out
}

/// Render an email address according to [`PiiLogMode`].
#[must_use]
pub fn format_email_for_log(email: &str, mode: PiiLogMode) -> String {
    match mode {
        PiiLogMode::Masked => redact_email(email),
        PiiLogMode::IdOnly => "[redacted]".to_owned(),
        PiiLogMode::Full => email.trim().to_owned(),
    }
}

/// Anonymize an IP address to its `/24` (IPv4) or `/48` (IPv6) subnet prefix.
///
/// Unparseable strings return `"[redacted]"` so raw values never leak through.
#[must_use]
pub fn truncate_ip(raw: &str) -> String {
    let Ok(ip) = raw.trim().parse::<IpAddr>() else {
        return "[redacted]".to_owned();
    };
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            format!("{}/24", Ipv4Addr::new(a, b, c, 0))
        }
        IpAddr::V6(v6) => {
            let [s0, s1, s2, _, _, _, _, _] = v6.segments();
            format!("{}/48", Ipv6Addr::new(s0, s1, s2, 0, 0, 0, 0, 0))
        }
    }
}

/// Apply [`AuditIpMode`] to an optional client IP address.
#[must_use]
pub fn format_ip_for_audit(ip: Option<&str>, mode: AuditIpMode) -> Option<String> {
    let raw = ip?;
    match mode {
        AuditIpMode::Full => Some(raw.trim().to_owned()),
        AuditIpMode::Truncated => Some(truncate_ip(raw)),
        AuditIpMode::None => None,
    }
}

/// Deterministic, non-routable RFC 2606 replacement email used during GDPR erasure.
///
/// Preserves unique email constraints on `auth_user` while removing all user PII.
#[must_use]
pub fn erased_email_for_user(user_id: Id) -> String {
    format!("erased-{user_id}@deleted.invalid")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_emails_preserving_leading_chars_and_domain() {
        assert_eq!(redact_email("wfischer@domain.com"), "wf******@domain.com");
        assert_eq!(redact_email("alice@example.org"), "al***@example.org");
        assert_eq!(redact_email("bob@example.org"), "b**@example.org");
        assert_eq!(redact_email("ab@example.org"), "a*@example.org");
        assert_eq!(redact_email("a@example.org"), "*@example.org");
        assert_eq!(redact_email("not-an-email"), "[redacted]");
    }

    #[test]
    fn formats_email_by_pii_log_mode() {
        assert_eq!(
            format_email_for_log("wfischer@domain.com", PiiLogMode::Masked),
            "wf******@domain.com"
        );
        assert_eq!(
            format_email_for_log("wfischer@domain.com", PiiLogMode::IdOnly),
            "[redacted]"
        );
        assert_eq!(
            format_email_for_log("wfischer@domain.com", PiiLogMode::Full),
            "wfischer@domain.com"
        );
    }

    #[test]
    fn truncates_ipv4_and_ipv6_subnets() {
        assert_eq!(truncate_ip("203.0.113.42"), "203.0.113.0/24");
        assert_eq!(
            truncate_ip("2001:db8:abcd:1234:5678::1"),
            "2001:db8:abcd::/48"
        );
        assert_eq!(truncate_ip("garbage"), "[redacted]");
        assert_eq!(
            format_ip_for_audit(Some("203.0.113.42"), AuditIpMode::None),
            None
        );
    }

    #[test]
    fn generates_rfc2606_erased_email() {
        let id = Id::now_v7();
        let erased = erased_email_for_user(id);
        assert!(erased.starts_with("erased-"));
        assert!(erased.ends_with("@deleted.invalid"));
    }
}
