use crate::error::DbError;
use crate::models::GlobalSettings;

/// Shared-pool global settings data access (singleton row, `id = 1`).
///
/// Object-safe via `async_trait` to support `Arc<dyn IGlobalSettingsRepository>`.
#[async_trait::async_trait]
pub trait IGlobalSettingsRepository: Send + Sync {
    /// Returns the current settings. If the singleton row is missing (should
    /// not happen — migration 045 seeds it), the defaults are returned.
    async fn get(&self) -> Result<GlobalSettings, DbError>;

    /// Inserts or overwrites the singleton settings row.
    async fn upsert(&self, settings: &GlobalSettings) -> Result<(), DbError>;
}
