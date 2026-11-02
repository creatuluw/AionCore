use crate::error::DbError;

/// Fair-use metering data access for the shared key pool.
///
/// Backed by the `usage_counters` table (migration 045): one row per
/// (user_id, provider_id, day) with a monotonically increasing request count.
#[async_trait::async_trait]
pub trait IUsageCounterRepository: Send + Sync {
    /// Atomically inserts or increments the counter for `(user_id, provider_id,
    /// day)` and returns the new count. The upsert-increment is a single SQL
    /// statement, so concurrent session builds against one shared provider each
    /// observe a distinct, gap-free count.
    async fn increment(&self, user_id: &str, provider_id: &str, day: &str) -> Result<i64, DbError>;

    /// Returns the current count for `(user_id, provider_id, day)` without
    /// incrementing. `0` when no counter row exists.
    async fn get(&self, user_id: &str, provider_id: &str, day: &str) -> Result<i64, DbError>;
}
