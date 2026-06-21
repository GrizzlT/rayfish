use std::collections::HashMap;

use anyhow::{Result, bail};
use iroh::EndpointId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Target {
    Tag(String),
    Identity(EndpointId),
    All,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AclRule {
    pub src: Target,
    pub dst: Target,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TagAssignment {
    pub tag: String,
    pub members: Vec<EndpointId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AclData {
    pub tags: Vec<TagAssignment>,
    pub rules: Vec<AclRule>,
}

impl AclData {
    pub fn empty() -> Self {
        Self {
            tags: vec![],
            rules: vec![],
        }
    }

    pub fn is_allowed(&self, src: &EndpointId, dst: &EndpointId) -> bool {
        if self.rules.is_empty() {
            return true;
        }
        let tag_map = self.build_tag_map();
        let src_tags = tag_map.get(src).cloned().unwrap_or_default();
        let dst_tags = tag_map.get(dst).cloned().unwrap_or_default();
        for rule in &self.rules {
            if target_matches(&rule.src, src, &src_tags)
                && target_matches(&rule.dst, dst, &dst_tags)
            {
                return true;
            }
        }
        false
    }

    fn build_tag_map(&self) -> HashMap<EndpointId, Vec<String>> {
        let mut map: HashMap<EndpointId, Vec<String>> = HashMap::new();
        for assignment in &self.tags {
            for member in &assignment.members {
                map.entry(*member).or_default().push(assignment.tag.clone());
            }
        }
        map
    }
}

fn target_matches(target: &Target, peer: &EndpointId, peer_tags: &[String]) -> bool {
    match target {
        Target::All => true,
        Target::Identity(id) => id == peer,
        Target::Tag(tag) => peer_tags.contains(tag),
    }
}

#[cfg(test)]
fn canonical_acl_bytes(data: &AclData) -> Vec<u8> {
    let mut sorted = data.clone();
    sorted.tags.sort_by(|a, b| a.tag.cmp(&b.tag));
    for assignment in &mut sorted.tags {
        assignment.members.sort_by_key(|m| m.to_string());
    }
    rmp_serde::to_vec_named(&sorted).expect("msgpack serialize")
}

#[cfg(test)]
fn acl_hash(data: &AclData) -> String {
    blake3::hash(&canonical_acl_bytes(data))
        .to_hex()
        .to_string()
}

#[cfg(test)]
fn decode_acl_data(bytes: &[u8]) -> Result<AclData> {
    rmp_serde::from_slice(bytes).map_err(|e| anyhow::anyhow!("invalid ACL data: {e}"))
}

#[cfg(test)]
fn verify_acl_data(bytes: &[u8], expected_hash: &str) -> Result<AclData> {
    let actual = blake3::hash(bytes).to_hex().to_string();
    if actual != expected_hash {
        bail!("ACL hash mismatch: expected {expected_hash}, got {actual}");
    }
    decode_acl_data(bytes)
}

pub fn parse_acl_file(
    content: &str,
    resolve_short_id: &dyn Fn(&str) -> Option<EndpointId>,
) -> Result<AclData> {
    let mut tags: Vec<TagAssignment> = Vec::new();
    let mut rules: Vec<AclRule> = Vec::new();

    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(rest) = line.strip_prefix("tag ") {
            let parts: Vec<&str> = rest.splitn(2, ' ').collect();
            if parts.len() < 2 {
                bail!(
                    "line {}: tag requires a name and at least one peer",
                    line_num + 1
                );
            }
            let tag_name = parts[0].to_string();
            let member_strs: Vec<&str> = parts[1]
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect();
            let mut members = Vec::new();
            for id_str in member_strs {
                let id = resolve_short_id(id_str).ok_or_else(|| {
                    anyhow::anyhow!("line {}: unknown peer '{}'", line_num + 1, id_str)
                })?;
                members.push(id);
            }
            tags.push(TagAssignment {
                tag: tag_name,
                members,
            });
        } else if let Some(rest) = line.strip_prefix("allow ") {
            let parts: Vec<&str> = rest.split("->").map(|s| s.trim()).collect();
            if parts.len() != 2 {
                bail!("line {}: allow rule must be 'src -> dst'", line_num + 1);
            }
            let src = parse_target(parts[0], resolve_short_id).ok_or_else(|| {
                anyhow::anyhow!("line {}: unknown src '{}'", line_num + 1, parts[0])
            })?;
            let dst = parse_target(parts[1], resolve_short_id).ok_or_else(|| {
                anyhow::anyhow!("line {}: unknown dst '{}'", line_num + 1, parts[1])
            })?;
            rules.push(AclRule { src, dst });
        } else {
            bail!("line {}: unrecognized directive '{}'", line_num + 1, line);
        }
    }

    Ok(AclData { tags, rules })
}

fn parse_target(s: &str, resolve_short_id: &dyn Fn(&str) -> Option<EndpointId>) -> Option<Target> {
    if s == "all" {
        Some(Target::All)
    } else if let Some(id) = resolve_short_id(s) {
        Some(Target::Identity(id))
    } else {
        // Treat as tag name (tags don't need resolution)
        Some(Target::Tag(s.to_string()))
    }
}

pub fn format_acl_file(data: &AclData, short_id: &dyn Fn(&EndpointId) -> String) -> String {
    let mut out = String::new();

    for assignment in &data.tags {
        let members: Vec<String> = assignment.members.iter().map(short_id).collect();
        out.push_str(&format!("tag {} {}\n", assignment.tag, members.join(", ")));
    }

    if !data.tags.is_empty() && !data.rules.is_empty() {
        out.push('\n');
    }

    for rule in &data.rules {
        out.push_str(&format!(
            "allow {} -> {}\n",
            format_target(&rule.src, short_id),
            format_target(&rule.dst, short_id)
        ));
    }

    out
}

fn format_target(target: &Target, short_id: &dyn Fn(&EndpointId) -> String) -> String {
    match target {
        Target::All => "all".to_string(),
        Target::Identity(id) => short_id(id),
        Target::Tag(tag) => tag.clone(),
    }
}

pub fn format_acl_show(data: &AclData, short_id: &dyn Fn(&EndpointId) -> String) -> String {
    if data.tags.is_empty() && data.rules.is_empty() {
        return "No ACL rules (allow-all).\n".to_string();
    }

    let mut out = String::new();

    if !data.tags.is_empty() {
        out.push_str("Tags:\n");
        for assignment in &data.tags {
            let members: Vec<String> = assignment.members.iter().map(short_id).collect();
            out.push_str(&format!("  {}: {}\n", assignment.tag, members.join(", ")));
        }
    }

    if !data.rules.is_empty() {
        out.push_str("Rules:\n");
        for (i, rule) in data.rules.iter().enumerate() {
            out.push_str(&format!(
                "  [{}] allow {} -> {}\n",
                i,
                format_target(&rule.src, short_id),
                format_target(&rule.dst, short_id),
            ));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_id(seed: u8) -> EndpointId {
        let mut key_bytes = [0u8; 32];
        key_bytes[0] = seed;
        iroh::SecretKey::from(key_bytes).public()
    }

    #[test]
    fn empty_acl_allows_all() {
        let acl = AclData::empty();
        assert!(acl.is_allowed(&test_id(1), &test_id(2)));
    }

    #[test]
    fn rules_deny_unmatched_traffic() {
        let acl = AclData {
            tags: vec![],
            rules: vec![AclRule {
                src: Target::Identity(test_id(1)),
                dst: Target::Identity(test_id(2)),
            }],
        };
        assert!(acl.is_allowed(&test_id(1), &test_id(2)));
        assert!(!acl.is_allowed(&test_id(2), &test_id(1)));
        assert!(!acl.is_allowed(&test_id(3), &test_id(1)));
    }

    #[test]
    fn tag_based_rules() {
        let acl = AclData {
            tags: vec![
                TagAssignment {
                    tag: "servers".to_string(),
                    members: vec![test_id(1), test_id(2)],
                },
                TagAssignment {
                    tag: "guests".to_string(),
                    members: vec![test_id(3)],
                },
            ],
            rules: vec![AclRule {
                src: Target::Tag("servers".to_string()),
                dst: Target::Tag("servers".to_string()),
            }],
        };
        assert!(acl.is_allowed(&test_id(1), &test_id(2)));
        assert!(acl.is_allowed(&test_id(2), &test_id(1)));
        assert!(!acl.is_allowed(&test_id(3), &test_id(1)));
    }

    #[test]
    fn all_target_matches_everyone() {
        let acl = AclData {
            tags: vec![],
            rules: vec![AclRule {
                src: Target::All,
                dst: Target::All,
            }],
        };
        assert!(acl.is_allowed(&test_id(1), &test_id(2)));
        assert!(acl.is_allowed(&test_id(99), &test_id(100)));
    }

    #[test]
    fn directional_rules() {
        let acl = AclData {
            tags: vec![
                TagAssignment {
                    tag: "servers".to_string(),
                    members: vec![test_id(1)],
                },
                TagAssignment {
                    tag: "guests".to_string(),
                    members: vec![test_id(2)],
                },
            ],
            rules: vec![AclRule {
                src: Target::Tag("guests".to_string()),
                dst: Target::Tag("servers".to_string()),
            }],
        };
        // guests -> servers allowed
        assert!(acl.is_allowed(&test_id(2), &test_id(1)));
        // servers -> guests NOT allowed (no rule for it)
        assert!(!acl.is_allowed(&test_id(1), &test_id(2)));
    }

    #[test]
    fn member_with_multiple_tags() {
        let acl = AclData {
            tags: vec![
                TagAssignment {
                    tag: "servers".to_string(),
                    members: vec![test_id(1)],
                },
                TagAssignment {
                    tag: "admin".to_string(),
                    members: vec![test_id(1)],
                },
            ],
            rules: vec![AclRule {
                src: Target::Tag("admin".to_string()),
                dst: Target::All,
            }],
        };
        assert!(acl.is_allowed(&test_id(1), &test_id(99)));
    }

    #[test]
    fn canonical_bytes_deterministic() {
        let acl = AclData {
            tags: vec![
                TagAssignment {
                    tag: "b".to_string(),
                    members: vec![test_id(2), test_id(1)],
                },
                TagAssignment {
                    tag: "a".to_string(),
                    members: vec![test_id(3)],
                },
            ],
            rules: vec![AclRule {
                src: Target::All,
                dst: Target::All,
            }],
        };
        let a = canonical_acl_bytes(&acl);
        let b = canonical_acl_bytes(&acl);
        assert_eq!(a, b);
    }

    #[test]
    fn canonical_bytes_order_independent() {
        let acl1 = AclData {
            tags: vec![
                TagAssignment {
                    tag: "b".to_string(),
                    members: vec![test_id(2), test_id(1)],
                },
                TagAssignment {
                    tag: "a".to_string(),
                    members: vec![test_id(3)],
                },
            ],
            rules: vec![],
        };
        let acl2 = AclData {
            tags: vec![
                TagAssignment {
                    tag: "a".to_string(),
                    members: vec![test_id(3)],
                },
                TagAssignment {
                    tag: "b".to_string(),
                    members: vec![test_id(1), test_id(2)],
                },
            ],
            rules: vec![],
        };
        assert_eq!(canonical_acl_bytes(&acl1), canonical_acl_bytes(&acl2));
    }

    #[test]
    fn acl_data_roundtrip() {
        let acl = AclData {
            tags: vec![TagAssignment {
                tag: "srv".to_string(),
                members: vec![test_id(1)],
            }],
            rules: vec![AclRule {
                src: Target::Tag("srv".to_string()),
                dst: Target::All,
            }],
        };
        let bytes = canonical_acl_bytes(&acl);
        let decoded = decode_acl_data(&bytes).unwrap();
        // After canonicalization both should match
        assert_eq!(canonical_acl_bytes(&decoded), bytes);
    }

    #[test]
    fn verify_acl_data_ok() {
        let acl = AclData {
            tags: vec![],
            rules: vec![AclRule {
                src: Target::All,
                dst: Target::All,
            }],
        };
        let bytes = canonical_acl_bytes(&acl);
        let hash = acl_hash(&acl);
        let decoded = verify_acl_data(&bytes, &hash).unwrap();
        assert_eq!(decoded.rules.len(), 1);
    }

    #[test]
    fn verify_acl_data_bad_hash() {
        let acl = AclData::empty();
        let bytes = canonical_acl_bytes(&acl);
        let result = verify_acl_data(&bytes, "badhash");
        assert!(result.is_err());
    }

    fn make_resolver<'a>(ids: &'a [(u8, &'a str)]) -> impl Fn(&str) -> Option<EndpointId> + 'a {
        move |s: &str| {
            ids.iter()
                .find(|(_, short)| *short == s)
                .map(|(seed, _)| test_id(*seed))
        }
    }

    #[test]
    fn parse_empty_file() {
        let resolver = make_resolver(&[]);
        let data = parse_acl_file("", &resolver).unwrap();
        assert!(data.tags.is_empty());
        assert!(data.rules.is_empty());
    }

    #[test]
    fn parse_comments_and_blank_lines() {
        let resolver = make_resolver(&[]);
        let data = parse_acl_file("# comment\n\n# another\n", &resolver).unwrap();
        assert!(data.tags.is_empty());
    }

    #[test]
    fn parse_tags_and_rules() {
        let resolver = make_resolver(&[(1, "ab3f"), (2, "d92c"), (3, "e71a")]);
        let content = "tag servers ab3f, d92c\ntag guests e71a\n\nallow servers -> servers\nallow guests -> all\n";
        let data = parse_acl_file(content, &resolver).unwrap();
        assert_eq!(data.tags.len(), 2);
        assert_eq!(data.tags[0].tag, "servers");
        assert_eq!(data.tags[0].members.len(), 2);
        assert_eq!(data.rules.len(), 2);
    }

    #[test]
    fn parse_rejects_unknown_directive() {
        let resolver = make_resolver(&[]);
        let result = parse_acl_file("deny foo -> bar", &resolver);
        assert!(result.is_err());
    }

    #[test]
    fn format_roundtrip() {
        let data = AclData {
            tags: vec![TagAssignment {
                tag: "servers".to_string(),
                members: vec![test_id(1), test_id(2)],
            }],
            rules: vec![AclRule {
                src: Target::Tag("servers".to_string()),
                dst: Target::All,
            }],
        };
        let short_id = |id: &EndpointId| -> String { id.fmt_short().to_string() };
        let text = format_acl_file(&data, &short_id);
        assert!(text.contains("tag servers"));
        assert!(text.contains("allow servers -> all"));
    }
}
