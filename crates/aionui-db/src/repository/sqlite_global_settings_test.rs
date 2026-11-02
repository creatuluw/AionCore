//! Integration tests for [`SqliteGlobalSettingsRepository`] over in-memory SQLite.

use crate::{GlobalSettings, IGlobalSettingsRepository, SqliteGlobalSettingsRepository, init_database_memory};

async fn repo() -> SqliteGlobalSettingsRepository {
    let db = init_database_memory().await.unwrap();
    SqliteGlobalSettingsRepository::new(db.pool().clone())
}

#[tokio::test]
async fn get_returns_seeded_defaults() {
    let repo = repo().await;
    let settings = repo.get().await.unwrap();
    assert_eq!(settings, GlobalSettings::default());
    assert!(!settings.shared_key_service_enabled);
    assert_eq!(settings.shared_pool_daily_request_cap, 100);
}

#[tokio::test]
async fn upsert_roundtrips_and_overwrites() {
    let repo = repo().await;

    let first = GlobalSettings {
        shared_key_service_enabled: true,
        shared_pool_daily_request_cap: 250,
    };
    repo.upsert(&first).await.unwrap();
    assert_eq!(repo.get().await.unwrap(), first);

    // Singleton: a second upsert overwrites the same row, not a second one.
    let second = GlobalSettings {
        shared_key_service_enabled: false,
        shared_pool_daily_request_cap: 1000,
    };
    repo.upsert(&second).await.unwrap();
    assert_eq!(repo.get().await.unwrap(), second);
}
