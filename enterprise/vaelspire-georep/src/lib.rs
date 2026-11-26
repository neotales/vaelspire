//! Copyright (c) Neotales. Proprietary — governed by `LICENSE-ENTERPRISE`.
//!
//! Multi-region tenant data residency enforcement ([`RegionPolicy`]) and
//! outbox-style cross-region replication log ([`ReplicationHook`]).

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use vaelspire_core::extensions::{RegionPolicy, ReplicationEvent, ReplicationHook};
use vaelspire_core::{AuthError, Id};

/// Lock-free tenant-to-region residency map implementing [`RegionPolicy`] (EU / US / APAC pinning).
#[derive(Debug, Clone)]
pub struct ResidencyPolicy {
    local_region: String,
    pins: HashMap<Id, String>,
}

impl ResidencyPolicy {
    /// Construct a policy for a Vaelspire node operating in `local_region` (e.g. `"eu-central-1"`).
    #[must_use]
    pub fn new(local_region: impl Into<String>) -> Self {
        Self {
            local_region: local_region.into(),
            pins: HashMap::new(),
        }
    }

    /// Pin `tenant_id` to an authoritative home region (e.g. `"eu-central-1"` or `"us-east-1"`).
    #[must_use]
    pub fn with_pin(mut self, tenant_id: Id, region: impl Into<String>) -> Self {
        self.pins.insert(tenant_id, region.into());
        self
    }

    /// Check whether a write for `tenant_id` is authorized to execute on this node.
    ///
    /// Returns `Ok(())` when the tenant is pinned to `local_region` (or unpinned), and
    /// `Err(home_region)` when the request must be routed to the tenant's home region.
    ///
    /// # Errors
    /// Returns the authoritative home region name when cross-region writes are disallowed.
    pub fn check_local_write(&self, tenant_id: Id) -> Result<(), &str> {
        let home = self.home_region(tenant_id);
        if home == self.local_region {
            Ok(())
        } else {
            Err(home)
        }
    }
}

impl RegionPolicy for ResidencyPolicy {
    fn local_region(&self) -> &str {
        &self.local_region
    }

    fn home_region(&self, tenant_id: Id) -> &str {
        self.pins
            .get(&tenant_id)
            .map_or(self.local_region.as_str(), String::as_str)
    }
}

/// Serializable envelope ready to ship to peer regions over mTLS / NATS / Kafka.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicationEnvelope {
    /// Monotonic local sequence number for cursor-based catchup.
    pub sequence: u64,
    /// Unique event ID from the originating node.
    pub event_id: String,
    /// Origin region that authored the mutation.
    pub origin_region: String,
    /// Tenant scope of the mutation.
    pub tenant_id: String,
    /// Stable mutation kind (e.g. `"session.revoked"`, `"user.created"`).
    pub kind: String,
    /// Identifier of the mutated entity.
    pub entity_id: String,
    /// Unix epoch timestamp when committed locally.
    pub occurred_at_unix: i64,
}

/// Outbox [`ReplicationHook`] capturing ordered, cross-region replication envelopes.
#[derive(Debug)]
pub struct ReplicationLogHook {
    envelopes: Mutex<Vec<ReplicationEnvelope>>,
}

impl Default for ReplicationLogHook {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplicationLogHook {
    /// Create an empty replication outbox.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            envelopes: Mutex::new(Vec::new()),
        }
    }

    /// Read all envelopes starting from `after_sequence` for peer-region pull sync.
    ///
    /// # Panics
    /// Never panics unless the internal mutex was poisoned.
    #[must_use]
    pub fn read_since(&self, after_sequence: u64) -> Vec<ReplicationEnvelope> {
        self.envelopes
            .lock()
            .expect("replication mutex poisoned")
            .iter()
            .filter(|env| env.sequence >= after_sequence)
            .cloned()
            .collect()
    }
}

#[async_trait]
impl ReplicationHook for ReplicationLogHook {
    async fn on_mutation(&self, event: ReplicationEvent) -> Result<(), AuthError> {
        let mut guard = self.envelopes.lock().map_err(|_| AuthError::Store)?;
        let sequence = u64::try_from(guard.len()).map_err(|_| AuthError::Store)?;
        guard.push(ReplicationEnvelope {
            sequence,
            event_id: event.id.to_string(),
            origin_region: event.origin_region,
            tenant_id: event.tenant_id.to_string(),
            kind: event.kind,
            entity_id: event.entity_id.to_string(),
            occurred_at_unix: event.occurred_at.unix_timestamp(),
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use vaelspire_core::Timestamp;

    use super::*;

    #[tokio::test]
    async fn residency_policy_pins_tenants_and_replication_hook_orders_envelopes() {
        let eu_tenant = Id::now_v7();
        let us_tenant = Id::now_v7();
        let policy = ResidencyPolicy::new("us-east-1").with_pin(eu_tenant, "eu-central-1");

        assert_eq!(policy.local_region(), "us-east-1");
        assert_eq!(policy.home_region(eu_tenant), "eu-central-1");
        assert_eq!(policy.home_region(us_tenant), "us-east-1");
        assert!(policy.is_local_tenant(us_tenant));
        assert!(!policy.is_local_tenant(eu_tenant));
        assert_eq!(policy.check_local_write(eu_tenant), Err("eu-central-1"));

        let hook = ReplicationLogHook::new();
        let ev = ReplicationEvent {
            id: Id::now_v7(),
            origin_region: "us-east-1".into(),
            tenant_id: us_tenant,
            kind: "session.revoked".into(),
            entity_id: Id::now_v7(),
            occurred_at: Timestamp::from_unix_timestamp(1_750_000_000).expect("ts"),
        };
        hook.on_mutation(ev.clone()).await.expect("publish 1");
        hook.on_mutation(ev).await.expect("publish 2");

        let all = hook.read_since(0);
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].sequence, 0);
        assert_eq!(all[1].sequence, 1);
        assert_eq!(hook.read_since(1).len(), 1);
    }
}
