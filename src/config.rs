use std::net::Ipv4Addr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use iroh::EndpointId;
use serde::{Deserialize, Serialize};

use crate::membership::GroupMode;

/// Info about a member in a saved network config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberEntry {
    pub identity: EndpointId,
    pub ip: Ipv4Addr,
    #[serde(default)]
    pub is_coordinator: bool,
}

/// A pre-approved peer that hasn't connected yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovedConfigEntry {
    pub identity: EndpointId,
    pub ip: Ipv4Addr,
}

/// A single saved network membership.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Human-friendly network alias (local only, not used for discovery).
    pub name: String,
    /// Membership mode: open or restricted.
    #[serde(default)]
    pub group_mode: GroupMode,
    /// Our assigned IP in this network (None if coordinator, Some if member).
    pub my_ip: Option<Ipv4Addr>,
    /// Known members in this network.
    #[serde(default)]
    pub members: Vec<MemberEntry>,
    /// Pre-approved peers that haven't connected yet.
    #[serde(default)]
    pub approved: Vec<ApprovedConfigEntry>,
    /// Per-network secret key (hex-encoded). Only present for coordinators.
    #[serde(default)]
    pub network_secret_key: Option<String>,
    /// Per-network public key (hex-encoded). The join code.
    #[serde(default)]
    pub network_public_key: Option<String>,
}

/// Top-level config stored at `~/.config/pitopi/networks.toml`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub networks: Vec<NetworkConfig>,
}

fn config_path() -> Result<PathBuf> {
    let dir = dirs::config_dir()
        .context("could not determine config directory")?
        .join("pitopi");
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join("networks.toml"))
}

/// Load the config file, returning a default empty config if it doesn't exist.
pub fn load() -> Result<AppConfig> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(AppConfig::default());
    }
    let contents = std::fs::read_to_string(&path).context("reading networks.toml")?;
    toml::from_str(&contents).context("parsing networks.toml")
}

/// Save the config file.
pub fn save(config: &AppConfig) -> Result<()> {
    let path = config_path()?;
    let contents = toml::to_string_pretty(config).context("serializing config")?;
    std::fs::write(&path, contents).context("writing networks.toml")?;
    Ok(())
}

/// Add or update a network in the config. If a network with the same name
/// already exists, it is replaced.
pub fn upsert_network(config: &mut AppConfig, network: NetworkConfig) {
    if let Some(existing) = config.networks.iter_mut().find(|n| n.name == network.name) {
        *existing = network;
    } else {
        config.networks.push(network);
    }
}

/// Remove a network by name. Returns true if it was found and removed.
pub fn remove_network(config: &mut AppConfig, name: &str) -> bool {
    let before = config.networks.len();
    config.networks.retain(|n| n.name != name);
    config.networks.len() < before
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::EndpointId;

    fn test_id(seed: u8) -> EndpointId {
        let mut key_bytes = [0u8; 32];
        key_bytes[0] = seed;
        iroh::SecretKey::from(key_bytes).public()
    }

    #[test]
    fn test_serialize_roundtrip() {
        let config = AppConfig {
            networks: vec![
                NetworkConfig {
                    name: "gaming".to_string(),
                    group_mode: GroupMode::Open,
                    my_ip: Some(Ipv4Addr::new(100, 64, 10, 5)),
                    members: vec![
                        MemberEntry {
                            identity: test_id(2),
                            ip: Ipv4Addr::new(100, 64, 5, 3),
                            is_coordinator: true,
                        },
                        MemberEntry {
                            identity: test_id(3),
                            ip: Ipv4Addr::new(100, 64, 10, 5),
                            is_coordinator: false,
                        },
                    ],
                    approved: vec![],
                    network_secret_key: None,
                    network_public_key: None,
                },
                NetworkConfig {
                    name: "work".to_string(),
                    group_mode: GroupMode::Restricted,
                    my_ip: None,
                    members: vec![],
                    approved: vec![],
                    network_secret_key: None,
                    network_public_key: None,
                },
            ],
        };

        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: AppConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(config, parsed);
    }

    #[test]
    fn test_deserialize_empty() {
        let config: AppConfig = toml::from_str("").unwrap();
        assert_eq!(config, AppConfig::default());
        assert!(config.networks.is_empty());
    }

    #[test]
    fn test_upsert_new() {
        let mut config = AppConfig::default();
        let net = NetworkConfig {
            name: "test".to_string(),
            group_mode: GroupMode::Open,
            my_ip: Some(Ipv4Addr::new(100, 64, 10, 5)),
            members: vec![],
            approved: vec![],
            network_secret_key: None,
            network_public_key: None,
        };
        upsert_network(&mut config, net.clone());
        assert_eq!(config.networks.len(), 1);
        assert_eq!(config.networks[0], net);
    }

    #[test]
    fn test_upsert_replaces_existing() {
        let mut config = AppConfig {
            networks: vec![NetworkConfig {
                name: "test".to_string(),
                group_mode: GroupMode::Restricted,
                my_ip: None,
                members: vec![],
                approved: vec![],
                network_secret_key: None,
                network_public_key: None,
            }],
        };
        let updated = NetworkConfig {
            name: "test".to_string(),
            group_mode: GroupMode::Open,
            my_ip: Some(Ipv4Addr::new(100, 64, 10, 5)),
            members: vec![],
            approved: vec![],
            network_secret_key: None,
            network_public_key: None,
        };
        upsert_network(&mut config, updated.clone());
        assert_eq!(config.networks.len(), 1);
        assert_eq!(config.networks[0].group_mode, GroupMode::Open);
        assert_eq!(config.networks[0].my_ip, Some(Ipv4Addr::new(100, 64, 10, 5)));
    }

    #[test]
    fn test_remove_network() {
        let mut config = AppConfig {
            networks: vec![
                NetworkConfig {
                    name: "keep".to_string(),
                    group_mode: GroupMode::Restricted,
                    my_ip: None,
                    members: vec![],
                    approved: vec![],
                    network_secret_key: None,
                    network_public_key: None,
                },
                NetworkConfig {
                    name: "remove-me".to_string(),
                    group_mode: GroupMode::Restricted,
                    my_ip: None,
                    members: vec![],
                    approved: vec![],
                    network_secret_key: None,
                    network_public_key: None,
                },
            ],
        };
        assert!(remove_network(&mut config, "remove-me"));
        assert_eq!(config.networks.len(), 1);
        assert_eq!(config.networks[0].name, "keep");
    }

    #[test]
    fn test_remove_nonexistent() {
        let mut config = AppConfig::default();
        assert!(!remove_network(&mut config, "nope"));
    }

    #[test]
    fn test_serialize_with_approved() {
        let id1 = test_id(1);
        let id2 = test_id(2);
        let config = AppConfig {
            networks: vec![NetworkConfig {
                name: "gaming".to_string(),
                group_mode: GroupMode::Restricted,
                my_ip: Some(Ipv4Addr::new(100, 64, 10, 5)),
                members: vec![MemberEntry {
                    identity: id1,
                    ip: Ipv4Addr::new(100, 64, 5, 3),
                    is_coordinator: true,
                }],
                approved: vec![ApprovedConfigEntry {
                    identity: id2,
                    ip: Ipv4Addr::new(100, 64, 12, 34),
                }],
                network_secret_key: None,
                network_public_key: None,
            }],
        };
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: AppConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(config, parsed);
        assert_eq!(parsed.networks[0].approved.len(), 1);
        assert_eq!(parsed.networks[0].approved[0].identity, id2);
    }

    #[test]
    fn test_serialize_with_network_key() {
        let config = AppConfig {
            networks: vec![NetworkConfig {
                name: "gaming".to_string(),
                group_mode: GroupMode::Restricted,
                my_ip: Some(Ipv4Addr::new(100, 64, 10, 5)),
                members: vec![],
                approved: vec![],
                network_secret_key: Some("deadbeef".to_string()),
                network_public_key: Some("cafebabe".to_string()),
            }],
        };
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: AppConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(config, parsed);
        assert_eq!(parsed.networks[0].network_public_key, Some("cafebabe".to_string()));
    }

    #[test]
    fn test_deserialize_minimal() {
        let toml_str = r#"
[[networks]]
name = "test"
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.networks.len(), 1);
        assert_eq!(config.networks[0].name, "test");
        assert_eq!(config.networks[0].group_mode, GroupMode::Restricted);
        assert!(config.networks[0].members.is_empty());
        assert!(config.networks[0].approved.is_empty());
        assert_eq!(config.networks[0].network_secret_key, None);
        assert_eq!(config.networks[0].network_public_key, None);
    }
}
