//! Extension trait seams for Vaelspire Core and Vaelspire Enterprise.
//!
//! Core ships zero-cost default implementations (`NoopAuditSink`, `NoopTelemetrySink`,
//! `CommunityLicenseGate`, `SingleRegionPolicy`, `NoopReplicationHook`). Commercial
//! Enterprise modules (maintained separately in the private `vaelspire-enterprise`
//! repository) implement these exact traits for WORM immutable storage,
//! SIEM/OpenTelemetry streaming, offline Ed25519 licensing, and multi-region
//! geo-replication — without refactoring core authentication logic.

use async_trait::async_trait;

use crate::{AuditEvent, AuthError, Id, Timestamp};

/// Enterprise capabilities gated behind a valid commercial license.
///
/// Core security features (Argon2id, sessions, MFA, Passkeys, OIDC, RBAC, Forward-Auth,
/// basic Prometheus metrics, and single-region audit logs) are NEVER placed in this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EnterpriseFeature {
    /// Active-active multi-region geo-replication and regional data-residency pinning.
    GeoReplication,
    /// Write-Once-Read-Many immutable audit storage (S3 Object Lock, Azure, GCS).
    WormStorage,
    /// Real-time SIEM and OpenTelemetry export pipelines.
    SiemTelemetry,
    /// Multi-year audit retention, cryptographic hash-chaining, and auditor portals.
    ExtendedAuditRetention,
    /// FIPS 140-3 validated cryptographic builds and formal compliance packages.
    Fips,
    /// Delegated multi-organization enterprise governance portals.
    MultiOrgGovernance,
}

impl EnterpriseFeature {
    /// Stable lowercase identifier used in offline license claims and diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GeoReplication => "geo_replication",
            Self::WormStorage => "worm_storage",
            Self::SiemTelemetry => "siem_telemetry",
            Self::ExtendedAuditRetention => "extended_audit_retention",
            Self::Fips => "fips",
            Self::MultiOrgGovernance => "multi_org_governance",
        }
    }

    /// Parse a stable feature claim identifier.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "geo_replication" => Some(Self::GeoReplication),
            "worm_storage" => Some(Self::WormStorage),
            "siem_telemetry" => Some(Self::SiemTelemetry),
            "extended_audit_retention" => Some(Self::ExtendedAuditRetention),
            "fips" => Some(Self::Fips),
            "multi_org_governance" => Some(Self::MultiOrgGovernance),
            _ => None,
        }
    }
}

/// Commercial capacity bounds encoded in a signed license.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LicenseLimits {
    /// Maximum number of active deployment regions (Core = 1).
    pub max_regions: u32,
    /// Optional workforce seat limit (`None` = unlimited).
    pub max_workforce_seats: Option<u64>,
    /// Optional high-volume CIAM monthly active user limit (`None` = unlimited).
    pub max_ciam_maus: Option<u64>,
}

impl Default for LicenseLimits {
    fn default() -> Self {
        Self {
            max_regions: 1,
            max_workforce_seats: None,
            max_ciam_maus: None,
        }
    }
}

/// Current licensing state observed by a [`LicenseGate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LicenseStatus {
    /// Free MIT Open-Core mode (1 region, unlimited community security).
    Community,
    /// Valid, unexpired commercial license.
    Licensed {
        /// Licensed organization or customer identifier.
        subject: String,
        /// Granted capacity limits.
        limits: LicenseLimits,
        /// Exclusive UTC expiry instant.
        expires_at: Timestamp,
    },
    /// License expired; logins remain unaffected while admins are alerted.
    GracePeriod {
        /// Licensed organization or customer identifier.
        subject: String,
        /// Previously granted capacity limits.
        limits: LicenseLimits,
        /// UTC instant when the license expired.
        expired_at: Timestamp,
    },
}

/// Commercial feature and capacity gate.
///
/// **Graceful enforcement invariant:** A license expiry or temporary seat overage
/// MUST NEVER break or block user authentication (`allows_login` always returns `true`).
pub trait LicenseGate: Send + Sync {
    /// Inspect the current license status at `now`.
    fn status(&self, now: Timestamp) -> LicenseStatus;

    /// Whether `feature` is permitted at `now`.
    fn allows_feature(&self, feature: EnterpriseFeature, now: Timestamp) -> bool;

    /// Maximum regions allowed by the current license (minimum 1).
    fn max_regions(&self, now: Timestamp) -> u32 {
        match self.status(now) {
            LicenseStatus::Community => 1,
            LicenseStatus::Licensed { limits, .. } | LicenseStatus::GracePeriod { limits, .. } => {
                limits.max_regions.max(1)
            }
        }
    }

    /// Authentication is never disabled by billing or license expiry.
    fn allows_login(&self) -> bool {
        true
    }
}

/// Default Open-Core license gate: 1 region, all core security free, enterprise features off.
#[derive(Debug, Default, Clone, Copy)]
pub struct CommunityLicenseGate;

impl LicenseGate for CommunityLicenseGate {
    fn status(&self, _now: Timestamp) -> LicenseStatus {
        LicenseStatus::Community
    }

    fn allows_feature(&self, _feature: EnterpriseFeature, _now: Timestamp) -> bool {
        false
    }
}

/// External audit archival sink (implemented by Enterprise WORM storage and SIEM exporters).
#[async_trait]
pub trait AuditSink: Send + Sync {
    /// Archive one validated, secret-free audit event recorded at `now`.
    ///
    /// # Errors
    /// Returns [`AuthError::Store`] if the sink cannot persist or buffer the event.
    async fn emit(&self, event: &AuditEvent, now: Timestamp) -> Result<(), AuthError>;
}

/// No-op audit sink used in Open-Core when only local transactional SQLite/Postgres audit is active.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopAuditSink;

#[async_trait]
impl AuditSink for NoopAuditSink {
    async fn emit(&self, _event: &AuditEvent, _now: Timestamp) -> Result<(), AuthError> {
        Ok(())
    }
}

/// Structured telemetry observation emitted by the server or auth engine.
///
/// Never carries passwords, tokens, session cookies, or raw API keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetrySignal {
    /// Stable metric or event name (e.g., `vaelspire.oidc.token.issued`).
    pub name: String,
    /// Stable outcome label (`ok`, `denied`, `error`).
    pub outcome: String,
    /// Optional tenant scope.
    pub tenant_id: Option<Id>,
    /// Deployment region identifier (e.g., `local`, `us-east-1`, `eu-central-1`).
    pub region: String,
    /// Operation latency in microseconds.
    pub latency_us: u64,
    /// Non-secret key/value attributes.
    pub attributes: Vec<(String, String)>,
}

/// Telemetry export seam (implemented by Enterprise OpenTelemetry / SIEM pipelines).
pub trait TelemetrySink: Send + Sync {
    /// Record one non-blocking telemetry observation.
    fn record(&self, signal: TelemetrySignal);
}

/// No-op telemetry sink for Open-Core deployments using built-in Prometheus `/metrics`.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopTelemetrySink;

impl TelemetrySink for NoopTelemetrySink {
    fn record(&self, _signal: TelemetrySignal) {}
}

/// Region and data-residency policy seam for multi-region Enterprise deployments.
pub trait RegionPolicy: Send + Sync {
    /// Identifier of the region running this process.
    fn local_region(&self) -> &str;

    /// Authoritative home region for `tenant_id` (enforces EU/US/APAC residency pinning).
    fn home_region(&self, tenant_id: Id) -> &str;

    /// Whether `tenant_id` is pinned to the local region.
    fn is_local_tenant(&self, tenant_id: Id) -> bool {
        self.home_region(tenant_id) == self.local_region()
    }
}

/// Default single-region policy for Vaelspire Core.
#[derive(Debug, Clone)]
pub struct SingleRegionPolicy {
    region: String,
}

impl SingleRegionPolicy {
    /// Construct a single-region policy with the given region label (e.g., `"local"`).
    #[must_use]
    pub fn new(region: impl Into<String>) -> Self {
        Self {
            region: region.into(),
        }
    }
}

impl Default for SingleRegionPolicy {
    fn default() -> Self {
        Self::new("local")
    }
}

impl RegionPolicy for SingleRegionPolicy {
    fn local_region(&self) -> &str {
        &self.region
    }

    fn home_region(&self, _tenant_id: Id) -> &str {
        &self.region
    }
}

/// Replication envelope describing an identity state transition for multi-region sync.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicationEvent {
    /// Monotonic or `UUIDv7` event identifier.
    pub id: Id,
    /// Tenant owning the mutated entity.
    pub tenant_id: Id,
    /// Originating region identifier.
    pub origin_region: String,
    /// Stable mutation kind (e.g., `session.revoked`, `user.created`, `api_key.revoked`).
    pub kind: String,
    /// Identifier of the mutated entity.
    pub entity_id: Id,
    /// UTC timestamp when the mutation committed locally.
    pub occurred_at: Timestamp,
}

/// Hook notified after committed security mutations so Enterprise can replicate across regions.
#[async_trait]
pub trait ReplicationHook: Send + Sync {
    /// Publish or enqueue one committed mutation for cross-region replication.
    ///
    /// # Errors
    /// Returns [`AuthError::Store`] if the replication transport rejects the envelope.
    async fn on_mutation(&self, event: ReplicationEvent) -> Result<(), AuthError>;
}

/// No-op replication hook for single-region Vaelspire Core.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopReplicationHook;

#[async_trait]
impl ReplicationHook for NoopReplicationHook {
    async fn on_mutation(&self, _event: ReplicationEvent) -> Result<(), AuthError> {
        Ok(())
    }
}
