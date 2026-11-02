use aionui_common::TimestampMs;

use crate::error::DbError;
use crate::models::InviteCodeRow;

/// Invite-code data access abstraction.
///
/// Codes are stored hashed (`code_hash`); the plaintext lives only in the
/// creation-time response. All methods return `Result<_, DbError>`.
///
/// Object-safe via `async_trait` to support `Arc<dyn IInviteCodeRepository>`.
#[async_trait::async_trait]
pub trait IInviteCodeRepository: Send + Sync {
    /// Inserts a new invite code row.
    ///
    /// Returns `DbError::Conflict` if the code hash already exists.
    async fn create(&self, row: &InviteCodeRow) -> Result<(), DbError>;

    /// Finds an unused/unrevoked-or-not invite code row by its SHA-256 hex hash.
    async fn find_by_code_hash(&self, code_hash: &str) -> Result<Option<InviteCodeRow>, DbError>;

    /// Atomically marks a code as used by `user_id`.
    ///
    /// Succeeds only if the code is still unused and unrevoked at update time
    /// (guarded in the WHERE clause); a code that was consumed or revoked
    /// concurrently yields `DbError::Conflict`.
    async fn mark_used(&self, id: &str, used_by: &str, used_at: TimestampMs) -> Result<(), DbError>;

    /// Marks a code revoked. Revoked codes are never redeemable. Revoking an
    /// already-revoked or used code is an idempotent no-op for revoked codes;
    /// an unknown id yields `DbError::NotFound`.
    async fn revoke(&self, id: &str, revoked_at: TimestampMs) -> Result<(), DbError>;

    /// Lists all invite codes, newest first.
    async fn list(&self) -> Result<Vec<InviteCodeRow>, DbError>;
}
