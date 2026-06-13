/// Wire shape of `GET {endpoint}/.well-known/kunobi-auth` — the auth-discovery
/// document a Kunobi service publishes so a client can bootstrap OIDC trust
/// (issuer + client_id [+ audience]). Shared by the client parser
/// (`client::discover`) and the server responder (`server::kunobi_auth_discovery_router`)
/// so the two can never drift.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KunobiAuthDiscovery {
    pub issuer: String,
    pub client_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The can't-drift guarantee: the wire shape is exactly `issuer`,
    /// `clientId` (camelCase), and an optional `audience` that is *present or
    /// absent* — never serialized as JSON `null`. A round-trip must reproduce
    /// the original value byte-for-byte at the type level.
    #[test]
    fn serializes_camel_case_with_present_audience() {
        let doc = KunobiAuthDiscovery {
            issuer: "https://auth.example.com".into(),
            client_id: "kobe-cli".into(),
            audience: Some("https://api.example.com".into()),
        };

        let json = serde_json::to_value(&doc).unwrap();
        assert_eq!(json["issuer"], "https://auth.example.com");
        assert_eq!(json["clientId"], "kobe-cli");
        assert_eq!(json["audience"], "https://api.example.com");
        // No snake_case leakage.
        assert!(json.get("client_id").is_none());

        let parsed: KunobiAuthDiscovery = serde_json::from_value(json).unwrap();
        assert_eq!(parsed, doc);
    }

    #[test]
    fn omits_audience_key_when_none() {
        let doc = KunobiAuthDiscovery {
            issuer: "https://auth.example.com".into(),
            client_id: "kobe-cli".into(),
            audience: None,
        };

        let json = serde_json::to_value(&doc).unwrap();
        assert_eq!(json["issuer"], "https://auth.example.com");
        assert_eq!(json["clientId"], "kobe-cli");
        // Absent — not present as JSON `null`.
        assert!(json.get("audience").is_none());

        let parsed: KunobiAuthDiscovery = serde_json::from_value(json).unwrap();
        assert_eq!(parsed, doc);
    }
}
