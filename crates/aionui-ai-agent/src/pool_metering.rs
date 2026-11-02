//! Shared-key-pool resolution and fair-use metering.
//!
//! A provider row the requester does NOT own is usable only when all of the
//! following hold:
//!
//! 1. the shared-key service is enabled (global settings),
//! 2. the row's visibility is `shared`,
//! 3. the row is enabled,
//! 4. the requester's per-day usage counter for that provider stays within
//!    `shared_pool_daily_request_cap` (`0` = unlimited).
//!
//! The counter increment is an atomic single-statement upsert (see
//! `IUsageCounterRepository`), so concurrent session builds each observe a
//! distinct count and the cap cannot be raced past.

use std::sync::Arc;

use aionui_db::{IGlobalSettingsRepository, IProviderRepository, IUsageCounterRepository, models::Provider};

use crate::error::AgentError;

/// UTC calendar day (`YYYY-MM-DD`) used as the metering bucket key.
fn utc_day_today() -> String {
    chrono::Utc::now().date_naive().to_string()
}

/// Fair-use meter for the shared key pool.
#[derive(Clone)]
pub struct SharedPoolMeter {
    usage_repo: Arc<dyn IUsageCounterRepository>,
    settings_repo: Option<Arc<dyn IGlobalSettingsRepository>>,
}

impl SharedPoolMeter {
    pub fn new(
        usage_repo: Arc<dyn IUsageCounterRepository>,
        settings_repo: Option<Arc<dyn IGlobalSettingsRepository>>,
    ) -> Self {
        Self {
            usage_repo,
            settings_repo,
        }
    }

    /// Decide whether `requester_id` may use `row`, metering the request when
    /// the row belongs to someone else (shared-pool use).
    ///
    /// Owner use passes through un-metered. Everything else requires the
    /// shared-key service to be on and the row to be a shared, enabled
    /// provider; inaccessible rows report `NotFound` so the pool's existence
    /// is not leaked to non-members.
    pub async fn authorize_shared_use(&self, requester_id: &str, row: &Provider) -> Result<(), AgentError> {
        if row.user_id == requester_id {
            return Ok(());
        }

        let settings = match self.settings_repo.as_ref() {
            Some(repo) => repo
                .get()
                .await
                .map_err(|e| AgentError::internal(format!("Failed to load shared-pool settings: {e}")))?,
            // No settings repository wired → sharing is disabled.
            None => aionui_db::GlobalSettings::default(),
        };

        let not_found = || AgentError::not_found(format!("Provider '{}' not found", row.id));
        if !settings.shared_key_service_enabled
            || row.visibility != aionui_db::ProviderVisibility::Shared.as_str()
            || !row.enabled
        {
            return Err(not_found());
        }

        let day = utc_day_today();
        let count = self
            .usage_repo
            .increment(requester_id, &row.id, &day)
            .await
            .map_err(|e| AgentError::internal(format!("Failed to record shared-pool usage: {e}")))?;

        if settings.shared_pool_daily_request_cap > 0 && count > settings.shared_pool_daily_request_cap {
            tracing::warn!(
                provider_id = %row.id,
                requester_id = %requester_id,
                day = %day,
                count,
                cap = settings.shared_pool_daily_request_cap,
                "shared-pool daily request cap exceeded"
            );
            return Err(AgentError::PoolQuotaExceeded);
        }

        Ok(())
    }
}

/// Resolve the provider row an agent build/probe will run with.
///
/// Owner-scoped lookup first (no metering). When the requester does not own
/// the row, fall back to the global lookup and meter the shared-pool use.
/// Rows that are private to someone else — or shared while the service is
/// off — surface as `NotFound`, identical to a missing id.
pub async fn resolve_provider_for_use(
    repo: &dyn IProviderRepository,
    meter: Option<&SharedPoolMeter>,
    requester_id: &str,
    provider_id: &str,
) -> Result<Provider, AgentError> {
    if let Some(row) = repo
        .find_by_id(requester_id, provider_id)
        .await
        .map_err(|e| AgentError::internal(format!("Failed to load provider config: {e}")))?
    {
        return Ok(row);
    }

    let row = repo
        .find_by_id_global(provider_id)
        .await
        .map_err(|e| AgentError::internal(format!("Failed to load provider config: {e}")))?
        .ok_or_else(|| AgentError::not_found(format!("Provider '{provider_id}' not found")))?;

    let Some(meter) = meter else {
        // Without the meter there is no way to authorize shared use; treat
        // the row as inaccessible (same as the service-disabled case).
        return Err(AgentError::not_found(format!("Provider '{provider_id}' not found")));
    };
    meter.authorize_shared_use(requester_id, &row).await?;
    Ok(row)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aionui_db::{CreateProviderParams, SqliteProviderRepository, SqliteUsageCounterRepository, init_database_memory};
    use std::time::Duration;

    const OWNER: &str = "system_default_user";
    const MEMBER: &str = "member_b";
    const KEY: [u8; 32] = [9u8; 32];

    /// In-memory database kept alive for the whole test body; the pool outlives
    /// the dropped handle (single connection, so state is shared).
    async fn db() -> sqlx::SqlitePool {
        let db = init_database_memory().await.unwrap();
        let pool = db.pool().clone();
        sqlx::query(
            "INSERT INTO users (id, user_type, username, password_hash, status, session_generation, created_at, updated_at) \
             VALUES (?, 'local', ?, '', 'active', 0, 1, 1)",
        )
        .bind(MEMBER)
        .bind(MEMBER)
        .execute(&pool)
        .await
        .unwrap();
        std::mem::forget(db);
        pool
    }

    async fn create_provider(pool: &sqlx::SqlitePool, id: &str, owner: &str, visibility: &str, enabled: bool) {
        let api_key_encrypted = aionui_common::encrypt_string("sk-test", &KEY).unwrap();
        SqliteProviderRepository::new(pool.clone())
            .create(CreateProviderParams {
                id: Some(id),
                user_id: owner,
                platform: "openai",
                name: id,
                base_url: "https://api.example.com",
                api_key_encrypted: &api_key_encrypted,
                visibility,
                models: r#"["m"]"#,
                enabled,
                capabilities: "[]",
                context_limit: None,
                model_protocols: None,
                model_enabled: None,
                model_health: None,
                model_settings: "{}",
                bedrock_config: None,
                is_full_url: false,
            })
            .await
            .unwrap();
    }

    fn meter(pool: &sqlx::SqlitePool, enabled: bool, cap: i64) -> impl std::future::Future<Output = SharedPoolMeter> {
        let settings_repo = aionui_db::SqliteGlobalSettingsRepository::new(pool.clone());
        let usage_repo = Arc::new(SqliteUsageCounterRepository::new(pool.clone()));
        async move {
            settings_repo
                .upsert(&aionui_db::GlobalSettings {
                    shared_key_service_enabled: enabled,
                    shared_pool_daily_request_cap: cap,
                })
                .await
                .unwrap();
            SharedPoolMeter::new(usage_repo, Some(Arc::new(settings_repo)))
        }
    }

    async fn usage_count(pool: &sqlx::SqlitePool, user: &str, provider: &str) -> i64 {
        SqliteUsageCounterRepository::new(pool.clone())
            .get(user, provider, &utc_day_today())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn owner_use_passes_without_metering() {
        let pool = db().await;
        create_provider(&pool, "prov-own", OWNER, "shared", true).await;
        let m = meter(&pool, true, 0).await;
        let row = resolve_provider_for_use(&SqliteProviderRepository::new(pool.clone()), Some(&m), OWNER, "prov-own")
            .await
            .unwrap();
        assert_eq!(row.user_id, OWNER);
        // No counter row may exist for the owner.
        assert_eq!(usage_count(&pool, OWNER, "prov-own").await, 0);
    }

    #[tokio::test]
    async fn shared_use_by_member_is_metered_once_per_resolve() {
        let pool = db().await;
        create_provider(&pool, "prov-pool", OWNER, "shared", true).await;
        let m = meter(&pool, true, 0).await;
        let repo = SqliteProviderRepository::new(pool.clone());

        for expected in [1_i64, 2, 3] {
            resolve_provider_for_use(&repo, Some(&m), MEMBER, "prov-pool").await.unwrap();
            assert_eq!(usage_count(&pool, MEMBER, "prov-pool").await, expected);
        }
    }

    #[tokio::test]
    async fn cap_exceeded_maps_to_pool_quota_exceeded() {
        let pool = db().await;
        create_provider(&pool, "prov-pool", OWNER, "shared", true).await;
        let m = meter(&pool, true, 2).await;
        let repo = SqliteProviderRepository::new(pool.clone());

        resolve_provider_for_use(&repo, Some(&m), MEMBER, "prov-pool").await.unwrap();
        resolve_provider_for_use(&repo, Some(&m), MEMBER, "prov-pool").await.unwrap();
        let err = resolve_provider_for_use(&repo, Some(&m), MEMBER, "prov-pool").await.unwrap_err();
        assert!(matches!(err, AgentError::PoolQuotaExceeded));
    }

    #[tokio::test]
    async fn zero_cap_means_unlimited() {
        let pool = db().await;
        create_provider(&pool, "prov-pool", OWNER, "shared", true).await;
        let m = meter(&pool, true, 0).await;
        let repo = SqliteProviderRepository::new(pool.clone());
        for _ in 0..25 {
            resolve_provider_for_use(&repo, Some(&m), MEMBER, "prov-pool").await.unwrap();
        }
    }

    #[tokio::test]
    async fn private_row_is_inaccessible_to_non_owner_even_when_enabled() {
        let pool = db().await;
        create_provider(&pool, "prov-private", OWNER, "private", true).await;
        let m = meter(&pool, true, 0).await;
        let repo = SqliteProviderRepository::new(pool.clone());
        let err = resolve_provider_for_use(&repo, Some(&m), MEMBER, "prov-private").await.unwrap_err();
        assert!(matches!(err, AgentError::NotFound(_)));
    }

    #[tokio::test]
    async fn shared_row_is_inaccessible_while_service_disabled() {
        let pool = db().await;
        create_provider(&pool, "prov-pool", OWNER, "shared", true).await;
        let m = meter(&pool, false, 0).await;
        let repo = SqliteProviderRepository::new(pool.clone());
        let err = resolve_provider_for_use(&repo, Some(&m), MEMBER, "prov-pool").await.unwrap_err();
        assert!(matches!(err, AgentError::NotFound(_)));
    }

    #[tokio::test]
    async fn disabled_shared_row_is_inaccessible_to_non_owner() {
        let pool = db().await;
        create_provider(&pool, "prov-off", OWNER, "shared", false).await;
        let m = meter(&pool, true, 0).await;
        let repo = SqliteProviderRepository::new(pool.clone());
        let err = resolve_provider_for_use(&repo, Some(&m), MEMBER, "prov-off").await.unwrap_err();
        assert!(matches!(err, AgentError::NotFound(_)));
    }

    #[tokio::test]
    async fn missing_meter_blocks_shared_fallback() {
        let pool = db().await;
        create_provider(&pool, "prov-pool", OWNER, "shared", true).await;
        let repo = SqliteProviderRepository::new(pool.clone());
        let err = resolve_provider_for_use(&repo, None, MEMBER, "prov-pool").await.unwrap_err();
        assert!(matches!(err, AgentError::NotFound(_)));
    }

    #[tokio::test]
    async fn unknown_id_is_not_found() {
        let pool = db().await;
        let m = meter(&pool, true, 0).await;
        let repo = SqliteProviderRepository::new(pool.clone());
        let err = resolve_provider_for_use(&repo, Some(&m), MEMBER, "no-such").await.unwrap_err();
        assert!(matches!(err, AgentError::NotFound(_)));
    }
}
