use std::net::Ipv4Addr;

use iroh::EndpointId;

pub trait IdentityProvider: Send + Sync {
    fn local_ip(&self) -> Ipv4Addr;
    fn local_identity(&self) -> String;
    fn derive_ip(&self, peer_identity: &str) -> Ipv4Addr;
    fn verify_peer(&self, claimed_identity: &str, transport_identity: &str) -> bool;
}

pub fn derive_ip(identity: &str) -> Ipv4Addr {
    let mut hash: u32 = 2_166_136_261; // FNV-1a offset basis
    for &b in identity.as_bytes() {
        hash ^= b as u32;
        hash = hash.wrapping_mul(16_777_619); // FNV-1a prime
    }

    let base: u32 = 0x6440_0000; // 100.64.0.0
    let host_bits = hash & 0x003F_FFFF; // lower 22 bits
    // Reserve 0 (network) and 1 (TUN gateway)
    let host_bits = if host_bits <= 1 {
        host_bits + 2
    } else {
        host_bits
    };
    Ipv4Addr::from(base | host_bits)
}

pub struct IrohIdentityProvider {
    endpoint_id: EndpointId,
    ip: Ipv4Addr,
}

impl IrohIdentityProvider {
    pub fn new(endpoint_id: EndpointId) -> Self {
        let ip = derive_ip(&endpoint_id.to_string());
        Self { endpoint_id, ip }
    }
}

impl IdentityProvider for IrohIdentityProvider {
    fn local_ip(&self) -> Ipv4Addr {
        self.ip
    }

    fn local_identity(&self) -> String {
        self.endpoint_id.to_string()
    }

    fn derive_ip(&self, peer_identity: &str) -> Ipv4Addr {
        derive_ip(peer_identity)
    }

    fn verify_peer(&self, claimed_identity: &str, transport_identity: &str) -> bool {
        claimed_identity == transport_identity
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_ip_deterministic() {
        let ip1 = derive_ip("abc123");
        let ip2 = derive_ip("abc123");
        assert_eq!(ip1, ip2);
    }

    #[test]
    fn test_derive_ip_in_cgnat_range() {
        let ip = derive_ip("test-identity-string");
        let octets = ip.octets();
        // 100.64.0.0/10 = first 10 bits fixed: 01100100.01xxxxxx
        assert_eq!(octets[0], 100);
        assert!(octets[1] >= 64 && octets[1] <= 127);
    }

    #[test]
    fn test_derive_ip_different_identities_differ() {
        let ip1 = derive_ip("identity-a");
        let ip2 = derive_ip("identity-b");
        assert_ne!(ip1, ip2);
    }

    #[test]
    fn test_derive_ip_avoids_reserved() {
        // Hash could theoretically land on 100.64.0.0 or 100.64.0.1
        // Test many inputs and verify none hit reserved addresses
        let reserved1 = Ipv4Addr::new(100, 64, 0, 0);
        let reserved2 = Ipv4Addr::new(100, 64, 0, 1);
        for i in 0..10000 {
            let ip = derive_ip(&format!("test-{i}"));
            assert_ne!(ip, reserved1);
            assert_ne!(ip, reserved2);
        }
    }

    #[test]
    fn test_iroh_identity_provider() {
        let key = iroh::SecretKey::generate();
        let endpoint_id = key.public();
        let provider = IrohIdentityProvider::new(endpoint_id);

        let ip = provider.local_ip();
        let octets = ip.octets();
        assert_eq!(octets[0], 100);
        assert!(octets[1] >= 64 && octets[1] <= 127);

        // derive_ip for same identity gives same result
        let id_str = provider.local_identity();
        assert_eq!(provider.derive_ip(&id_str), ip);
    }

    #[test]
    fn test_iroh_verify_peer() {
        let key = iroh::SecretKey::generate();
        let endpoint_id = key.public();
        let provider = IrohIdentityProvider::new(endpoint_id);

        let id_str = endpoint_id.to_string();
        assert!(provider.verify_peer(&id_str, &id_str));
        assert!(!provider.verify_peer("wrong-identity", &id_str));
    }
}
