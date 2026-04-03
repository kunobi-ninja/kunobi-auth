use std::collections::HashMap;
use tokio::sync::RwLock;

/// Tracks concurrent active requests per identity.
pub struct RateLimiter {
    active: RwLock<HashMap<String, u32>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            active: RwLock::new(HashMap::new()),
        }
    }

    /// Try to acquire a slot. Returns false if at limit.
    pub async fn try_acquire(&self, identity: &str, max_concurrent: u32) -> bool {
        let mut active = self.active.write().await;
        let count = active.entry(identity.to_string()).or_insert(0);
        if *count >= max_concurrent {
            false
        } else {
            *count += 1;
            true
        }
    }

    /// Release a slot.
    pub async fn release(&self, identity: &str) {
        let mut active = self.active.write().await;
        if let Some(count) = active.get_mut(identity) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                active.remove(identity);
            }
        }
    }

    /// Get current count for an identity.
    pub async fn current(&self, identity: &str) -> u32 {
        self.active.read().await.get(identity).copied().unwrap_or(0)
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}
