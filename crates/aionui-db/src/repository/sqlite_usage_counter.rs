use sqlx::SqlitePool;

use crate::error::DbError;
use crate::repository::IUsageCounterRepository;

/// SQLite-backed implementation of [`IUsageCounterRepository`].
#[derive(Clone, Debug)]
pub struct SqliteUsageCounterRepository {
    pool: SqlitePool,
}

impl SqliteUsageCounterRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl IUsageCounterRepository for SqliteUsageCounterRepository {
    async fn increment(&self, user_id: &str, provider_id: &str, day: &str) -> Result<i64, DbError> {
        // Single-statement upsert-increment: the INSERT ... ON CONFLICT DO
        // UPDATE and the RETURNING of the post-write value are atomic within
        // one SQLite write transaction, so two concurrent requesters each get
        // a distinct count (the fair-use cap can never be raced past).
        let count: i64 =
            sqlx::query_scalar(
                "INSERT INTO usage_counters (user_id, provider_id, day, requests) VALUES (?, ?, ?, 1) \
                 ON CONFLICT(user_id, provider_id, day) DO UPDATE SET requests = requests + 1 \
                 RETURNING requests",
            )
            .bind(user_id)
            .bind(provider_id)
            .bind(day)
            .fetch_one(&self.pool)
            .await
            .map_err(DbError::Query)?;

        Ok(count)
    }

    async fn get(&self, user_id: &str, provider_id: &str, day: &str) -> Result<i64, DbError> {
        let count: Option<i64> = sqlx::query_scalar("SELECT requests FROM usage_counters WHERE user_id = ? AND provider_id = ? AND day = ?")
            .bind(user_id)
            .bind(provider_id)
            .bind(day)
            .fetch_optional(&self.pool)
            .await
            .map_err(DbError::Query)?;

        Ok(count.unwrap_or(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init_database_memory;

    const USER: &str = "system_default_user";
    const PROVIDER: &str = "prov_shared_1";

    async fn setup() -> SqliteUsageCounterRepository {
        let db = init_database_memory().await.unwrap();
        let repo = SqliteUsageCounterRepository::new(db.pool().clone());
        // Keep the in-memory database alive for the whole test body.
        std::mem::forget(db);
        repo
    }

    #[tokio::test]
    async fn increment_starts_at_one_and_counts_up() {
        let repo = setup().await;
        assert_eq!(repo.increment(USER, PROVIDER, "2026-11-02").await.unwrap(), 1);
        assert_eq!(repo.increment(USER, PROVIDER, "2026-11-02").await.unwrap(), 2);
        assert_eq!(repo.increment(USER, PROVIDER, "2026-11-02").await.unwrap(), 3);
    }

    #[tokio::test]
    async fn counters_are_per_user_and_per_day() {
        let repo = setup().await;
        repo.increment(USER, PROVIDER, "2026-11-02").await.unwrap();
        repo.increment(USER, PROVIDER, "2026-11-02").await.unwrap();

        // Different user
        assert_eq!(repo.get("member_b", PROVIDER, "2026-11-02").await.unwrap(), 0);
        repo.increment("member_b", PROVIDER, "2026-11-02").await.unwrap();
        assert_eq!(repo.get(USER, PROVIDER, "2026-11-02").await.unwrap(), 2);

        // Different day
        assert_eq!(repo.get(USER, PROVIDER, "2026-11-03").await.unwrap(), 0);
        repo.increment(USER, PROVIDER, "2026-11-03").await.unwrap();
        assert_eq!(repo.get(USER, PROVIDER, "2026-11-02").await.unwrap(), 2);

        // Different provider
        assert_eq!(repo.get(USER, "prov_other", "2026-11-02").await.unwrap(), 0);
    }

    #[tokio::test]
    async fn get_missing_row_returns_zero() {
        let repo = setup().await;
        assert_eq!(repo.get(USER, PROVIDER, "2026-11-02").await.unwrap(), 0);
    }
}
