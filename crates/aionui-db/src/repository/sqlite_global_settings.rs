use sqlx::SqlitePool;

use crate::error::DbError;
use crate::models::GlobalSettings;
use crate::repository::IGlobalSettingsRepository;

/// Singleton row id for `global_settings`.
const SETTINGS_ROW_ID: i64 = 1;

/// SQLite-backed implementation of [`IGlobalSettingsRepository`].
#[derive(Clone, Debug)]
pub struct SqliteGlobalSettingsRepository {
    pool: SqlitePool,
}

impl SqliteGlobalSettingsRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl IGlobalSettingsRepository for SqliteGlobalSettingsRepository {
    async fn get(&self) -> Result<GlobalSettings, DbError> {
        let row: Option<(bool, i64)> = sqlx::query_as(
            "SELECT shared_key_service_enabled, shared_pool_daily_request_cap \
             FROM global_settings WHERE id = ?",
        )
        .bind(SETTINGS_ROW_ID)
        .fetch_optional(&self.pool)
        .await?;

        // Migration 045 seeds the singleton, so a missing row is only reachable
        // on a corrupted/foreign database; serve defaults rather than failing.
        Ok(row
            .map(|(enabled, cap)| GlobalSettings {
                shared_key_service_enabled: enabled,
                shared_pool_daily_request_cap: cap,
            })
            .unwrap_or_default())
    }

    async fn upsert(&self, settings: &GlobalSettings) -> Result<(), DbError> {
        sqlx::query(
            "INSERT INTO global_settings (id, shared_key_service_enabled, shared_pool_daily_request_cap) \
             VALUES (?, ?, ?) \
             ON CONFLICT(id) DO UPDATE SET \
                 shared_key_service_enabled = excluded.shared_key_service_enabled, \
                 shared_pool_daily_request_cap = excluded.shared_pool_daily_request_cap",
        )
        .bind(SETTINGS_ROW_ID)
        .bind(settings.shared_key_service_enabled)
        .bind(settings.shared_pool_daily_request_cap)
        .execute(&self.pool)
        .await
        .map_err(DbError::Query)?;

        Ok(())
    }
}

#[cfg(test)]
#[path = "sqlite_global_settings_test.rs"]
mod sqlite_global_settings_test;
