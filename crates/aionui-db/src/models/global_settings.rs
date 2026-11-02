use serde::{Deserialize, Serialize};

/// Row mapping for the `global_settings` singleton table (`id = 1`).
///
/// Holds shared-key-pool configuration: whether the shared-key service is
/// enabled and the daily request cap applied to the shared pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlobalSettings {
    /// Whether provider API keys may be shared pool-wide.
    pub shared_key_service_enabled: bool,
    /// Daily request cap for the shared pool, across all members.
    pub shared_pool_daily_request_cap: i64,
}

impl Default for GlobalSettings {
    fn default() -> Self {
        Self {
            shared_key_service_enabled: false,
            shared_pool_daily_request_cap: 100,
        }
    }
}
