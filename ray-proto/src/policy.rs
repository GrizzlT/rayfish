//! Coordinator-suggested firewall rules, distributed in the signed `GroupBlob`.
//!
//! These types are the single authoritative shape for a trusted network's
//! suggested firewall: they ride in the blob, cross the IPC boundary
//! ([`crate::ipc::IpcMessage::FirewallSuggest`]), and are what a `ray apply`
//! spec deserializes into. They are deliberately keyed by **hostname**, so an
//! admin can author rules before any host has joined; each node materializes
//! the rules targeting its own hostname, resolving peer hostnames to identities
//! from the same blob's member list.
//!
//! [`BTreeMap`] keys give a canonical (sorted) serialization, so the blob hash
//! is stable regardless of authoring order.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Suggested firewall rules for one subject host, keyed by peer hostname.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostSuggestions {
    /// Catch-all action for traffic on this network to the subject ("allow" |
    /// "deny"). When `Some("deny")` (or an allow-list is present) the node
    /// installs a trailing network-scoped deny so only the listed peers pass.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    /// peer hostname -> comma-separated ports (e.g. `"9000,8123"` or `"9999"`):
    /// the subject accepts inbound from that peer on those ports.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub allows: BTreeMap<String, String>,
    /// peer hostname -> ports the subject explicitly denies inbound from.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub denies: BTreeMap<String, String>,
}

/// Subject hostname -> its suggested rules. Sorted keys ⇒ canonical bytes.
pub type SuggestedFirewall = BTreeMap<String, HostSuggestions>;
