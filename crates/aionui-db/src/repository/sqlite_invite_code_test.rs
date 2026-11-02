//! Integration tests for [`SqliteInviteCodeRepository`] over in-memory SQLite.

use crate::{DbError, IInviteCodeRepository, InviteCodeRow, SqliteInviteCodeRepository, init_database_memory};
use aionui_common::now_ms;

async fn repo() -> SqliteInviteCodeRepository {
    let db = init_database_memory().await.unwrap();
    SqliteInviteCodeRepository::new(db.pool().clone())
}

fn row(code_hash: &str, created_by: &str, expires_at: Option<i64>) -> InviteCodeRow {
    InviteCodeRow {
        id: aionui_common::generate_prefixed_id("invite"),
        code_hash: code_hash.to_owned(),
        created_by: created_by.to_owned(),
        created_at: now_ms(),
        expires_at,
        used_by: None,
        used_at: None,
        revoked_at: None,
    }
}

#[tokio::test]
async fn create_and_find_by_hash_roundtrips() {
    let repo = repo().await;
    let invite = row("hash-abc", "system_default_user", None);
    repo.create(&invite).await.unwrap();

    let found = repo.find_by_code_hash("hash-abc").await.unwrap().unwrap();
    assert_eq!(found.id, invite.id);
    assert_eq!(found.code_hash, "hash-abc");
    assert_eq!(found.created_by, "system_default_user");
    assert_eq!(found.expires_at, None);
    assert_eq!(found.used_by, None);
    assert_eq!(found.revoked_at, None);
}

#[tokio::test]
async fn find_unknown_hash_returns_none() {
    let repo = repo().await;
    assert!(repo.find_by_code_hash("missing").await.unwrap().is_none());
}

#[tokio::test]
async fn duplicate_code_hash_conflicts() {
    let repo = repo().await;
    repo.create(&row("dup-hash", "system_default_user", None))
        .await
        .unwrap();
    let err = repo
        .create(&row("dup-hash", "system_default_user", None))
        .await
        .unwrap_err();
    assert!(matches!(err, DbError::Conflict(_)), "expected Conflict, got {err:?}");
}

#[tokio::test]
async fn mark_used_records_redeemer_and_is_one_shot() {
    let repo = repo().await;
    let invite = row("hash-use", "system_default_user", None);
    repo.create(&invite).await.unwrap();

    repo.mark_used(&invite.id, "user-1", now_ms()).await.unwrap();
    let used = repo.find_by_code_hash("hash-use").await.unwrap().unwrap();
    assert_eq!(used.used_by.as_deref(), Some("user-1"));
    assert!(used.used_at.is_some());

    // A second redemption attempt loses the race by contract.
    let err = repo.mark_used(&invite.id, "user-2", now_ms()).await.unwrap_err();
    assert!(matches!(err, DbError::Conflict(_)), "expected Conflict, got {err:?}");
}

#[tokio::test]
async fn mark_used_on_revoked_code_conflicts() {
    let repo = repo().await;
    let invite = row("hash-revoked", "system_default_user", None);
    repo.create(&invite).await.unwrap();
    repo.revoke(&invite.id, now_ms()).await.unwrap();

    let err = repo.mark_used(&invite.id, "user-1", now_ms()).await.unwrap_err();
    assert!(matches!(err, DbError::Conflict(_)), "expected Conflict, got {err:?}");
}

#[tokio::test]
async fn mark_used_unknown_id_conflicts() {
    let repo = repo().await;
    let err = repo.mark_used("no-such-id", "user-1", now_ms()).await.unwrap_err();
    assert!(matches!(err, DbError::Conflict(_)), "expected Conflict, got {err:?}");
}

#[tokio::test]
async fn revoke_marks_code_and_is_idempotent() {
    let repo = repo().await;
    let invite = row("hash-revoke", "system_default_user", None);
    repo.create(&invite).await.unwrap();

    repo.revoke(&invite.id, now_ms()).await.unwrap();
    let revoked = repo.find_by_code_hash("hash-revoke").await.unwrap().unwrap();
    assert!(revoked.revoked_at.is_some());

    // Revoking twice is a no-op, not an error.
    repo.revoke(&invite.id, now_ms()).await.unwrap();
}

#[tokio::test]
async fn revoke_unknown_id_is_not_found() {
    let repo = repo().await;
    let err = repo.revoke("no-such-id", now_ms()).await.unwrap_err();
    assert!(matches!(err, DbError::NotFound(_)), "expected NotFound, got {err:?}");
}

#[tokio::test]
async fn list_returns_newest_first() {
    let repo = repo().await;
    let older = InviteCodeRow {
        created_at: now_ms() - 10_000,
        ..row("hash-old", "admin-a", None)
    };
    let newer = row("hash-new", "admin-a", None);
    repo.create(&older).await.unwrap();
    repo.create(&newer).await.unwrap();

    let invites = repo.list().await.unwrap();
    assert_eq!(invites.len(), 2);
    assert_eq!(invites[0].code_hash, "hash-new");
    assert_eq!(invites[1].code_hash, "hash-old");
}
