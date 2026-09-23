//! Generic authorization primitives shared by Kunobi services.
//!
//! This module owns only the parts every consumer would otherwise hand-roll:
//! claim extraction (via [`AuthIdentity`] accessors), a single claim-equality
//! match ([`ClaimMatch`]), a conjunction of claim allow-lists ([`ClaimRule`]),
//! and deny-by-default first-match evaluators ([`first_match`],
//! [`first_rule_match`]) that are generic over the consumer's outcome type.
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

/// One clause of a [`ClaimRule`]: the claim at `claim` (dot-path) is one of
/// `values`.
///
/// An empty `values` list matches nothing, so a clause can never widen access
/// by being left empty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimAllowed {
    /// Dot-path of the claim to inspect (e.g. `repository_owner`).
    pub claim: String,
    /// Values the claim may take.
    pub values: Vec<String>,
    /// Compare ASCII case-insensitively, for claims such as GitHub owner and
    /// repository names whose case the platform does not treat as meaningful.
    #[serde(default)]
    pub ignore_ascii_case: bool,
}

impl ClaimAllowed {
    /// The claim at `claim` is one of `values`, compared exactly.
    pub fn any_of(
        claim: impl Into<String>,
        values: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            claim: claim.into(),
            values: values.into_iter().map(Into::into).collect(),
            ignore_ascii_case: false,
        }
    }

    /// Compare ASCII case-insensitively.
    pub fn ignoring_ascii_case(mut self) -> Self {
        self.ignore_ascii_case = true;
        self
    }

    /// Returns `true` when `identity`'s claim at [`claim`](Self::claim)
    /// coerces (via [`AuthIdentity::claim_str`]) to one of
    /// [`values`](Self::values).
    pub fn matches(&self, identity: &AuthIdentity) -> bool {
        let Some(actual) = identity.claim_str(&self.claim) else {
            return false;
        };
        self.values.iter().any(|value| {
            if self.ignore_ascii_case {
                value.eq_ignore_ascii_case(&actual)
            } else {
                *value == actual
            }
        })
    }
}

impl From<ClaimMatch> for ClaimAllowed {
    fn from(m: ClaimMatch) -> Self {
        Self::any_of(m.claim, [m.value])
    }
}

/// Every clause must hold. A rule with no clauses matches nothing: use an
/// absent rule, not an empty one, to express "unconditional".
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimRule {
    pub all: Vec<ClaimAllowed>,
}

impl ClaimRule {
    pub fn new(all: impl IntoIterator<Item = ClaimAllowed>) -> Self {
        Self {
            all: all.into_iter().collect(),
        }
    }

    /// Adds a clause.
    pub fn and(mut self, clause: ClaimAllowed) -> Self {
        self.all.push(clause);
        self
    }

    /// Returns `true` when the rule has at least one clause and every clause
    /// matches `identity`.
    pub fn matches(&self, identity: &AuthIdentity) -> bool {
        !self.all.is_empty() && self.all.iter().all(|clause| clause.matches(identity))
    }
}

/// [`first_match`] for rules carrying a [`ClaimRule`]: the first rule whose
/// `ClaimRule` is absent (unconditional) or matches, or `None` to deny.
pub fn first_rule_match<'a, R>(
    rules: &'a [R],
    identity: &AuthIdentity,
    rule_of: impl Fn(&'a R) -> Option<&'a ClaimRule>,
) -> Option<&'a R> {
    rules.iter().find(|rule| match rule_of(rule) {
        None => true,
        Some(r) => r.matches(identity),
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

    #[test]
    fn allowed_matches_any_listed_value() {
        let id = identity_with(serde_json::json!({"repository_owner": "Zondax"}));
        assert!(ClaimAllowed::any_of("repository_owner", ["kunobi-ninja", "Zondax"]).matches(&id));
        assert!(!ClaimAllowed::any_of("repository_owner", ["zondax"]).matches(&id));
        assert!(
            ClaimAllowed::any_of("repository_owner", ["zondax"])
                .ignoring_ascii_case()
                .matches(&id)
        );
        assert!(!ClaimAllowed::any_of("repository_owner", Vec::<String>::new()).matches(&id));
        assert!(!ClaimAllowed::any_of("missing", ["Zondax"]).matches(&id));
    }

    #[test]
    fn a_rule_needs_every_clause_and_at_least_one() {
        let id = identity_with(serde_json::json!({
            "repository_owner": "Zondax",
            "ref": "refs/heads/main",
        }));
        let owner = ClaimAllowed::any_of("repository_owner", ["Zondax"]);
        let main = ClaimAllowed::any_of("ref", ["refs/heads/main"]);
        let other = ClaimAllowed::any_of("ref", ["refs/heads/dev"]);
        assert!(ClaimRule::new([owner.clone()]).and(main).matches(&id));
        assert!(!ClaimRule::new([owner]).and(other).matches(&id));
        assert!(!ClaimRule::default().matches(&id));
    }

    #[test]
    fn a_claim_match_converts_to_a_single_value_clause() {
        let clause: ClaimAllowed = ClaimMatch {
            claim: "role".to_string(),
            value: "admin".to_string(),
        }
        .into();
        assert_eq!(clause, ClaimAllowed::any_of("role", ["admin"]));
    }

    #[test]
    fn first_rule_match_takes_the_first_applicable_rule_or_denies() {
        let id = identity_with(serde_json::json!({"role": "admin"}));
        let rules = [
            (
                Some(ClaimRule::new([ClaimAllowed::any_of("role", ["user"])])),
                "user",
            ),
            (
                Some(ClaimRule::new([ClaimAllowed::any_of("role", ["admin"])])),
                "admin",
            ),
            (None, "anyone"),
        ];
        let hit = first_rule_match(&rules, &id, |r| r.0.as_ref());
        assert_eq!(hit.map(|r| r.1), Some("admin"));
        let hit = first_rule_match(&rules[..1], &id, |r| r.0.as_ref());
        assert!(hit.is_none());
        let hit = first_rule_match(&rules[2..], &id, |r| r.0.as_ref());
        assert_eq!(hit.map(|r| r.1), Some("anyone"));
    }

    #[test]
    fn a_rule_round_trips_through_serde_with_case_defaulting_off() {
        let rule: ClaimRule = serde_json::from_value(serde_json::json!({
            "all": [{"claim": "repository_owner", "values": ["Zondax"]}]
        }))
        .unwrap();
        assert_eq!(
            rule,
            ClaimRule::new([ClaimAllowed::any_of("repository_owner", ["Zondax"])])
        );
    }
}
