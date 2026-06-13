use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Validated identity extracted from a request.
///
/// Contains the authenticated caller's identity and raw claims.
/// AuthZ decisions are left to the consuming service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthIdentity {
    /// Provider identifier (e.g. access policy name).
    pub provider: String,
    /// Identity string (from template interpolation).
    pub identity: String,
    /// Method used to authenticate ("oidc", "token").
    pub method: String,
    /// Raw claims from the JWT (OIDC) or empty for token auth.
    /// Services use these for their own authorization decisions.
    #[serde(default)]
    pub claims: HashMap<String, serde_json::Value>,
}

impl AuthIdentity {
    /// Look up a claim by dot-path into the raw [`claims`](Self::claims) map.
    ///
    /// The path is split on `'.'`; the first segment indexes the claims map and
    /// each remaining segment traverses into nested JSON objects (via
    /// [`serde_json::Value::get`]). Returns `None` if any segment is missing or
    /// the path is empty.
    ///
    /// This reads the *raw* claims with no special-casing, so a JWT `sub` is
    /// simply `claim("sub")`.
    pub fn claim(&self, path: &str) -> Option<&serde_json::Value> {
        let mut parts = path.split('.');
        let mut current = self.claims.get(parts.next()?)?;
        for part in parts {
            current = current.get(part)?;
        }
        Some(current)
    }

    /// Look up a claim by dot-path (see [`claim`](Self::claim)) and coerce it to
    /// a `String`.
    ///
    /// `String` values are returned as-is; numbers and booleans use their
    /// `to_string()` form; any other value (array/object/null) is rendered as
    /// its JSON form. Returns `None` if the claim is missing.
    ///
    /// Like [`claim`](Self::claim), this reads raw claims with no special-casing.
    pub fn claim_str(&self, path: &str) -> Option<String> {
        match self.claim(path)? {
            serde_json::Value::String(s) => Some(s.clone()),
            v @ (serde_json::Value::Number(_) | serde_json::Value::Bool(_)) => Some(v.to_string()),
            v => Some(v.to_string()),
        }
    }

    /// The OAuth `scope` claim split on ASCII whitespace.
    ///
    /// Returns an empty vector when the `scope` claim is absent or not a string.
    pub fn scopes(&self) -> Vec<&str> {
        self.claims
            .get("scope")
            .and_then(serde_json::Value::as_str)
            .map(|s| s.split_whitespace().collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_identity() -> AuthIdentity {
        let mut claims = HashMap::new();
        claims.insert("sub".to_string(), serde_json::json!("user-123"));
        claims.insert("email".to_string(), serde_json::json!("a@b.com"));
        AuthIdentity {
            provider: "my-oidc".to_string(),
            identity: "user-123".to_string(),
            method: "oidc".to_string(),
            claims,
        }
    }

    #[test]
    fn test_serialize_deserialize_with_claims() {
        let id = sample_identity();
        let json = serde_json::to_string(&id).unwrap();
        let deserialized: AuthIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.provider, "my-oidc");
        assert_eq!(deserialized.identity, "user-123");
        assert_eq!(deserialized.method, "oidc");
        assert_eq!(deserialized.claims.len(), 2);
        assert_eq!(deserialized.claims["sub"], serde_json::json!("user-123"));
        assert_eq!(deserialized.claims["email"], serde_json::json!("a@b.com"));
    }

    #[test]
    fn test_empty_claims() {
        let id = AuthIdentity {
            provider: "token-auth".to_string(),
            identity: "svc-account".to_string(),
            method: "token".to_string(),
            claims: HashMap::new(),
        };
        let json = serde_json::to_string(&id).unwrap();
        let deserialized: AuthIdentity = serde_json::from_str(&json).unwrap();
        assert!(deserialized.claims.is_empty());
        assert_eq!(deserialized.method, "token");
    }

    #[test]
    fn test_deserialize_without_claims_field_uses_default() {
        let json = r#"{"provider":"p","identity":"i","method":"m"}"#;
        let id: AuthIdentity = serde_json::from_str(json).unwrap();
        assert!(id.claims.is_empty());
    }

    #[test]
    fn test_roundtrip_json() {
        let original = sample_identity();
        let json = serde_json::to_value(&original).unwrap();
        let back: AuthIdentity = serde_json::from_value(json).unwrap();
        assert_eq!(back.provider, original.provider);
        assert_eq!(back.identity, original.identity);
        assert_eq!(back.method, original.method);
        assert_eq!(back.claims.len(), original.claims.len());
    }

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
    fn test_claim_nested_dot_path() {
        let id = identity_with(serde_json::json!({"private_metadata": {"role": "admin"}}));
        assert_eq!(
            id.claim("private_metadata.role"),
            Some(&serde_json::json!("admin"))
        );
    }

    #[test]
    fn test_claim_missing_path() {
        let id = identity_with(serde_json::json!({"private_metadata": {"role": "admin"}}));
        assert_eq!(id.claim("private_metadata.team"), None);
        assert_eq!(id.claim("nope"), None);
        assert_eq!(id.claim(""), None);
    }

    #[test]
    fn test_claim_top_level_hit() {
        let id = identity_with(serde_json::json!({"sub": "user-123"}));
        assert_eq!(id.claim("sub"), Some(&serde_json::json!("user-123")));
    }

    #[test]
    fn test_claim_str_string_as_is() {
        let id = identity_with(serde_json::json!({"sub": "user-123"}));
        assert_eq!(id.claim_str("sub"), Some("user-123".to_string()));
    }

    #[test]
    fn test_claim_str_number() {
        let id = identity_with(serde_json::json!({"n": 42}));
        assert_eq!(id.claim_str("n"), Some("42".to_string()));
    }

    #[test]
    fn test_claim_str_bool() {
        let id = identity_with(serde_json::json!({"b": true}));
        assert_eq!(id.claim_str("b"), Some("true".to_string()));
    }

    #[test]
    fn test_claim_str_object_json_form() {
        let id = identity_with(serde_json::json!({"o": {"k": "v"}}));
        assert_eq!(id.claim_str("o"), Some(r#"{"k":"v"}"#.to_string()));
    }

    #[test]
    fn test_claim_str_missing() {
        let id = identity_with(serde_json::json!({}));
        assert_eq!(id.claim_str("nope"), None);
    }

    #[test]
    fn test_scopes_split() {
        let id = identity_with(serde_json::json!({"scope": "a b  c"}));
        assert_eq!(id.scopes(), vec!["a", "b", "c"]);
    }

    #[test]
    fn test_scopes_missing() {
        let id = identity_with(serde_json::json!({}));
        assert!(id.scopes().is_empty());
    }
}
