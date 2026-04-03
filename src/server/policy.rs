use crate::common::identity::ResolvedAuth;
use crate::common::rules::AccessRule;
use std::collections::HashMap;

/// Engine that matches identities to access rules.
pub struct PolicyEngine {
    providers: Vec<CompiledPolicy>,
}

struct CompiledPolicy {
    name: String,
    issuer: Option<String>,
    identity_template: String,
    rules: Vec<AccessRule>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
        }
    }

    /// Add a policy (called when access policies change).
    pub fn add_policy(
        &mut self,
        name: &str,
        issuer: Option<&str>,
        identity_template: &str,
        rules: Vec<AccessRule>,
    ) {
        self.providers.push(CompiledPolicy {
            name: name.to_string(),
            issuer: issuer.map(|s| s.to_string()),
            identity_template: identity_template.to_string(),
            rules,
        });
    }

    /// Clear all policies.
    pub fn clear(&mut self) {
        self.providers.clear();
    }

    /// Find matching policy by issuer.
    pub fn find_by_issuer(&self, issuer: &str) -> Option<&str> {
        self.providers
            .iter()
            .find(|p| p.issuer.as_deref() == Some(issuer))
            .map(|p| p.name.as_str())
    }

    /// Match an identity against rules, returning the resolved authorization.
    pub fn resolve(
        &self,
        policy_name: &str,
        claims: &HashMap<String, serde_json::Value>,
    ) -> Option<(String, ResolvedAuth)> {
        let policy = self.providers.iter().find(|p| p.name == policy_name)?;

        // Build identity from template
        let identity = interpolate_template(&policy.identity_template, claims);

        // Find first matching rule
        for rule in &policy.rules {
            if let Some(ref match_clause) = rule.match_clause {
                let claim_value = get_claim(claims, &match_clause.claim)?;
                if claim_value != match_clause.value {
                    continue;
                }
            }

            let max_ttl = parse_duration(&rule.max_ttl).unwrap_or(chrono::Duration::hours(1));

            return Some((
                identity,
                ResolvedAuth {
                    allowed_resources: rule.resources.clone(),
                    max_ttl,
                    max_concurrent: rule.max_concurrent,
                    max_extensions: rule.max_extensions,
                },
            ));
        }

        None
    }

    /// Check if a resource matches the allowed patterns.
    pub fn is_resource_allowed(resource: &str, allowed: &[String]) -> bool {
        for pattern in allowed {
            if pattern == "*" {
                return true;
            }
            if pattern.ends_with('*') {
                let prefix = &pattern[..pattern.len() - 1];
                if resource.starts_with(prefix) {
                    return true;
                }
            }
            if pattern == resource {
                return true;
            }
        }
        false
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

fn interpolate_template(template: &str, claims: &HashMap<String, serde_json::Value>) -> String {
    let mut result = template.to_string();
    for (key, value) in claims {
        let placeholder = format!("{{{key}}}");
        if let Some(s) = value.as_str() {
            result = result.replace(&placeholder, s);
        }
    }
    result
}

fn get_claim(claims: &HashMap<String, serde_json::Value>, path: &str) -> Option<String> {
    let parts: Vec<&str> = path.split('.').collect();
    let mut current: &serde_json::Value = claims.get(parts[0])?;
    for part in &parts[1..] {
        current = current.get(part)?;
    }
    current.as_str().map(|s| s.to_string())
}

fn parse_duration(s: &str) -> Option<chrono::Duration> {
    let s = s.trim();
    let mut total_seconds: i64 = 0;
    let mut current_num = String::new();
    for ch in s.chars() {
        if ch.is_ascii_digit() {
            current_num.push(ch);
        } else {
            let n: i64 = current_num.parse().ok()?;
            current_num.clear();
            total_seconds += match ch {
                'h' => n * 3600,
                'm' => n * 60,
                's' => n,
                _ => return None,
            };
        }
    }
    chrono::Duration::try_seconds(total_seconds)
}
