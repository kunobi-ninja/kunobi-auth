/// Static token authentication (for CI, scripts, service accounts).
pub struct StaticTokenAuth {
    token: String,
}

impl StaticTokenAuth {
    /// Create a static token provider from a token value.
    pub fn new(token: String) -> Self {
        Self { token }
    }

    /// Return the configured token value.
    pub fn token(&self) -> &str {
        &self.token
    }
}
