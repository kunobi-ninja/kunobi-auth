//! Generic authorization primitives shared by Kunobi services.
//!
//! This module owns only the parts every consumer would otherwise hand-roll:
//! claim extraction (via [`AuthIdentity`] accessors), a single claim-equality
//! match ([`ClaimMatch`]), and a deny-by-default first-match evaluator
//! ([`first_match`]) that is generic over the consumer's outcome type.
//!
//! It is deliberately **not** a policy engine. Resource graphs, RBAC bindings,
//! and the meaning of a matched rule (pools, TTLs, the consumer's `Policy`,
//! etc.) all stay with the consumer: [`first_match`] simply hands back the
//! first matching rule and lets the caller interpret it.

use crate::common::identity::AuthIdentity;
use serde::{Deserialize, Serialize};

/// A single condition — the claim at `claim` (dot-path) equals `value`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimMatch {
    /// Dot-path of the claim to inspect (e.g. `private_metadata.role`).
    pub claim: String,
    /// Value the claim must equal.
    pub value: String,
}

impl ClaimMatch {
    /// Returns `true` when `identity`'s claim at [`claim`](Self::claim) coerces
    /// (via [`AuthIdentity::claim_str`]) to exactly [`value`](Self::value).
    pub fn matches(&self, identity: &AuthIdentity) -> bool {
        identity.claim_str(&self.claim).as_deref() == Some(self.value.as_str())
    }
}

/// Select the first rule that applies to `identity`, or deny by default.
///
/// `match_of` projects a consumer rule `R` to its optional [`ClaimMatch`]
/// clause. A rule applies when it has no clause (`None`, unconditional) or its
/// clause matches the identity. Returns the first such rule, or `None` if none
/// apply — that `None` **is** the deny-by-default decision.
///
/// `R` is the consumer's outcome type; the library never inspects the policy it
/// carries.
pub fn first_match<'a, R>(
    rules: &'a [R],
    identity: &AuthIdentity,
    match_of: impl Fn(&'a R) -> Option<&'a ClaimMatch>,
) -> Option<&'a R> {
    rules.iter().find(|rule| match match_of(rule) {
        None => true,
        Some(m) => m.matches(identity),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn identity_with(claims: serde_json::Value) -> AuthIdentity {
        let claims = match claims {
            serde_json::Value::Object(map) => map.into_iter().collect(),
            _ => HashMap::new(),
        };
        AuthIdentity {
            provider: "p".to_string(),
            identity: "i".to_string(),
            method: "oidc".to_string(),
            claims,
        }
    }

    #[test]
    fn test_matches_equal() {
        let id = identity_with(serde_json::json!({"role": "admin"}));
        let m = ClaimMatch {
            claim: "role".to_string(),
            value: "admin".to_string(),
        };
        assert!(m.matches(&id));
    }

    #[test]
    fn test_matches_different_value() {
        let id = identity_with(serde_json::json!({"role": "user"}));
        let m = ClaimMatch {
            claim: "role".to_string(),
            value: "admin".to_string(),
        };
        assert!(!m.matches(&id));
    }

    #[test]
    fn test_matches_missing_claim() {
        let id = identity_with(serde_json::json!({}));
        let m = ClaimMatch {
            claim: "role".to_string(),
            value: "admin".to_string(),
        };
        assert!(!m.matches(&id));
    }

    #[test]
    fn test_matches_nested_path() {
        let id = identity_with(serde_json::json!({"private_metadata": {"role": "admin"}}));
        let m = ClaimMatch {
            claim: "private_metadata.role".to_string(),
            value: "admin".to_string(),
        };
        assert!(m.matches(&id));
    }

    struct Rule {
        m: Option<ClaimMatch>,
        tag: &'static str,
    }

    #[test]
    fn test_first_match_satisfied_rule_wins() {
        let id = identity_with(serde_json::json!({"role": "admin"}));
        let rules = vec![
            Rule {
                m: Some(ClaimMatch {
                    claim: "role".to_string(),
                    value: "user".to_string(),
                }),
                tag: "user-rule",
            },
            Rule {
                m: Some(ClaimMatch {
                    claim: "role".to_string(),
                    value: "admin".to_string(),
                }),
                tag: "admin-rule",
            },
        ];
        let hit = first_match(&rules, &id, |r| r.m.as_ref());
        assert_eq!(hit.map(|r| r.tag), Some("admin-rule"));
    }

    #[test]
    fn test_first_match_unconditional_rule() {
        let id = identity_with(serde_json::json!({"role": "nobody"}));
        let rules = vec![
            Rule {
                m: Some(ClaimMatch {
                    claim: "role".to_string(),
                    value: "admin".to_string(),
                }),
                tag: "admin-rule",
            },
            Rule {
                m: None,
                tag: "fallback",
            },
        ];
        let hit = first_match(&rules, &id, |r| r.m.as_ref());
        assert_eq!(hit.map(|r| r.tag), Some("fallback"));
    }

    #[test]
    fn test_first_match_deny_by_default() {
        let id = identity_with(serde_json::json!({"role": "nobody"}));
        let rules = vec![Rule {
            m: Some(ClaimMatch {
                claim: "role".to_string(),
                value: "admin".to_string(),
            }),
            tag: "admin-rule",
        }];
        let hit = first_match(&rules, &id, |r| r.m.as_ref());
        assert!(hit.is_none());
    }
}
