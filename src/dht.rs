//! DHT-based membership publishing and resolution.
//!
//! Encodes network membership as signed pkarr DNS TXT records and publishes them
//! to the iroh pkarr relay so peers can discover each other without the coordinator
//! being online.
//!
//! # Record format
//!
//! TXT records are stored under the `_pitopi` DNS name:
//!
//! ```text
//! "v1"                             // version sentinel (always first)
//! "c,<hex_identity>"               // coordinator member
//! "m,<hex_identity>"               // regular member
//! "a,<hex_identity>"               // approved (not yet connected)
//! ```
//!
//! IPs are not stored — they are reconstructed on decode via [`derive_ip`].

use anyhow::{Context as _, Result, bail, ensure};
use iroh::{
    EndpointId, SecretKey,
    address_lookup::PkarrRelayClient,
    dns::DnsResolver,
    endpoint::Endpoint,
};
use iroh_dns::pkarr::SignedPacket;
use url::Url;

use crate::membership::{ApprovedEntry, ApprovedList, Member, MemberList, derive_ip};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const RECORD_NAME: &str = "_pitopi";
const RECORD_VERSION: &str = "v1";
const RECORD_TTL: u32 = 300;
/// The production pkarr relay run by number 0.
const PKARR_RELAY_URL: &str = "https://dns.iroh.link/pkarr";

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// Derives a deterministic `SecretKey` for this network's DHT membership record.
///
/// The coordinator publishes membership under this key so that peers can find it
/// using only the coordinator's public key and the network name.
pub fn derive_membership_key(coordinator_key: &SecretKey, network_name: &str) -> SecretKey {
    let context = format!("pitopi/membership/{network_name}");
    let derived = blake3::derive_key(&context, &coordinator_key.to_bytes());
    SecretKey::from_bytes(&derived)
}

/// Returns the `EndpointId` (public key) under which membership is published on the DHT.
pub fn membership_dht_id(coordinator_key: &SecretKey, network_name: &str) -> EndpointId {
    derive_membership_key(coordinator_key, network_name).public()
}

// ---------------------------------------------------------------------------
// Record encoding / decoding
// ---------------------------------------------------------------------------

/// Encodes the current membership state into a signed pkarr packet.
pub fn encode_membership_record(
    key: &SecretKey,
    members: &MemberList,
    approved: &ApprovedList,
) -> Result<SignedPacket> {
    let mut values = vec![RECORD_VERSION.to_string()];

    for m in members.all() {
        let role = if m.is_coordinator { "c" } else { "m" };
        values.push(format!("{role},{}", m.identity));
    }

    for a in approved.all() {
        values.push(format!("a,{}", a.identity));
    }

    SignedPacket::from_txt_strings(key, RECORD_NAME, values, RECORD_TTL)
        .map_err(|e| anyhow::anyhow!("failed to build signed packet: {e}"))
}

/// Decodes a signed pkarr packet into member and approved-entry lists.
///
/// IPs are reconstructed deterministically via [`derive_ip`].
pub fn decode_membership_record(
    packet: &SignedPacket,
) -> Result<(Vec<Member>, Vec<ApprovedEntry>)> {
    let records = packet.txt_records(RECORD_NAME);
    ensure!(!records.is_empty(), "no membership records found");
    ensure!(
        records[0] == RECORD_VERSION,
        "unsupported record version: {}",
        records[0]
    );

    let mut members = Vec::new();
    let mut approved = Vec::new();

    for record in &records[1..] {
        let (tag, identity_str) = record
            .split_once(',')
            .context("invalid record format: missing comma separator")?;
        let identity: EndpointId = identity_str
            .parse()
            .context("invalid identity in membership record")?;
        match tag {
            "c" => members.push(Member {
                ip: derive_ip(&identity),
                identity,
                is_coordinator: true,
            }),
            "m" => members.push(Member {
                ip: derive_ip(&identity),
                identity,
                is_coordinator: false,
            }),
            "a" => approved.push(ApprovedEntry {
                ip: derive_ip(&identity),
                identity,
            }),
            _ => bail!("unknown record tag: {tag}"),
        }
    }

    Ok((members, approved))
}

// ---------------------------------------------------------------------------
// Pkarr client
// ---------------------------------------------------------------------------

/// Creates a [`PkarrRelayClient`] using the endpoint's TLS and DNS configuration.
pub fn create_pkarr_client(ep: &Endpoint) -> Result<PkarrRelayClient> {
    let tls_config = ep.tls_config().clone();
    let dns_resolver: DnsResolver = ep
        .dns_resolver()
        .context("endpoint has no DNS resolver")?
        .clone();
    let relay_url: Url = PKARR_RELAY_URL.parse().expect("relay URL is valid");
    Ok(PkarrRelayClient::new(relay_url, tls_config, dns_resolver))
}

// ---------------------------------------------------------------------------
// Publish / resolve
// ---------------------------------------------------------------------------

/// Encodes the membership state and publishes it to the pkarr relay.
pub async fn publish_membership(
    client: &PkarrRelayClient,
    key: &SecretKey,
    members: &MemberList,
    approved: &ApprovedList,
) -> Result<()> {
    let packet = encode_membership_record(key, members, approved)?;
    client
        .publish(&packet)
        .await
        .map_err(|e| anyhow::anyhow!("failed to publish membership: {e}"))
}

/// Resolves and decodes membership from the pkarr relay.
pub async fn resolve_membership(
    client: &PkarrRelayClient,
    dht_id: EndpointId,
) -> Result<(Vec<Member>, Vec<ApprovedEntry>)> {
    let packet = client
        .resolve(dht_id)
        .await
        .map_err(|e| anyhow::anyhow!("failed to resolve membership: {e}"))?;
    decode_membership_record(&packet)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;
    use std::net::Ipv4Addr;

    fn test_key(seed: u8) -> SecretKey {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        SecretKey::from_bytes(&bytes)
    }

    fn test_id(seed: u8) -> EndpointId {
        test_key(seed).public()
    }

    // -- Key derivation -------------------------------------------------------

    #[test]
    fn test_derive_membership_key_deterministic() {
        let key = SecretKey::generate();
        let k1 = derive_membership_key(&key, "gaming");
        let k2 = derive_membership_key(&key, "gaming");
        assert_eq!(k1.public(), k2.public());
    }

    #[test]
    fn test_derive_membership_key_differs_by_network() {
        let key = SecretKey::generate();
        let k1 = derive_membership_key(&key, "gaming");
        let k2 = derive_membership_key(&key, "work");
        assert_ne!(k1.public(), k2.public());
    }

    #[test]
    fn test_membership_dht_id() {
        let key = SecretKey::generate();
        let dht_id = membership_dht_id(&key, "gaming");
        let derived = derive_membership_key(&key, "gaming");
        assert_eq!(dht_id, derived.public());
    }

    // -- Encode / decode roundtrip -------------------------------------------

    #[test]
    fn test_encode_decode_roundtrip() {
        let key = SecretKey::generate();
        let mut members = MemberList::new();
        members
            .add(Member {
                identity: test_id(1),
                ip: Ipv4Addr::new(100, 64, 0, 2),
                is_coordinator: true,
            })
            .unwrap();
        members
            .add(Member {
                identity: test_id(2),
                ip: Ipv4Addr::new(100, 64, 0, 3),
                is_coordinator: false,
            })
            .unwrap();

        let approved = ApprovedList::new();

        let packet = encode_membership_record(&key, &members, &approved).unwrap();
        let (decoded_members, decoded_approved) = decode_membership_record(&packet).unwrap();

        assert_eq!(decoded_members.len(), 2);
        assert_eq!(decoded_approved.len(), 0);
        assert!(decoded_members.iter().any(|m| m.is_coordinator));
    }

    #[test]
    fn test_encode_decode_with_approved() {
        let key = SecretKey::generate();
        let coord_id = test_id(1);
        let pending_id = test_id(3);

        let mut members = MemberList::new();
        members
            .add(Member {
                identity: coord_id,
                ip: derive_ip(&coord_id),
                is_coordinator: true,
            })
            .unwrap();

        let mut approved = ApprovedList::new();
        approved
            .approve(
                ApprovedEntry {
                    identity: pending_id,
                    ip: derive_ip(&pending_id),
                },
                &members,
            )
            .unwrap();

        let packet = encode_membership_record(&key, &members, &approved).unwrap();
        let (dec_m, dec_a) = decode_membership_record(&packet).unwrap();

        assert_eq!(dec_m.len(), 1);
        assert_eq!(dec_a.len(), 1);
        assert_eq!(dec_m[0].identity, coord_id);
        assert_eq!(dec_a[0].identity, pending_id);
        // IPs are reconstructed via derive_ip
        assert_eq!(dec_m[0].ip, derive_ip(&coord_id));
        assert_eq!(dec_a[0].ip, derive_ip(&pending_id));
    }

    #[test]
    fn test_encode_decode_empty() {
        let key = SecretKey::generate();
        let members = MemberList::new();
        let approved = ApprovedList::new();

        let packet = encode_membership_record(&key, &members, &approved).unwrap();
        let (dec_m, dec_a) = decode_membership_record(&packet).unwrap();

        assert!(dec_m.is_empty());
        assert!(dec_a.is_empty());
    }

    #[test]
    fn test_record_version_check() {
        let key = SecretKey::generate();
        let members = MemberList::new();
        let approved = ApprovedList::new();
        let packet = encode_membership_record(&key, &members, &approved).unwrap();
        let records = packet.txt_records("_pitopi");
        assert_eq!(records[0], "v1");
    }

    #[test]
    fn test_derive_membership_key_differs_from_source() {
        // The derived key for a network should differ from the coordinator's own key
        let key = SecretKey::generate();
        let derived = derive_membership_key(&key, "gaming");
        assert_ne!(key.public(), derived.public());
    }

    #[test]
    fn test_decode_rejects_unknown_version() {
        // Build a packet with an unknown version
        let key = SecretKey::generate();
        let values = vec!["v99".to_string()];
        let packet =
            SignedPacket::from_txt_strings(&key, "_pitopi", values, 300).unwrap();
        let result = decode_membership_record(&packet);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unsupported record version"));
    }

    #[test]
    fn test_decode_rejects_empty_packet() {
        // A packet with no _pitopi records at all
        let key = SecretKey::generate();
        // Use a different record name so _pitopi has no entries
        let values = vec!["v1".to_string()];
        let packet =
            SignedPacket::from_txt_strings(&key, "_other", values, 300).unwrap();
        let result = decode_membership_record(&packet);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no membership records found"));
    }

    #[test]
    fn test_decode_rejects_unknown_tag() {
        let key = SecretKey::generate();
        let packet = SignedPacket::from_txt_strings(
            &key,
            "_pitopi",
            vec!["v1", "x,some_identity"],
            300,
        ).unwrap();
        let result = decode_membership_record(&packet);
        assert!(result.is_err());
    }
}
