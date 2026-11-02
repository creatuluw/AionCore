use aionui_common::TimestampMs;
use serde::{Deserialize, Serialize};

/// Row mapping for the `invite_codes` table.
///
/// Only the SHA-256 hex hash of an invite code is stored (`code_hash`); the
/// plaintext is shown to the creating admin exactly once at creation time and
/// never persisted.
///
/// Lifecycle: created → (optionally revoked) → (optionally used). A code is
/// redeemable only while `revoked_at`, `used_by`, and `used_at` are all NULL
/// and `expires_at` is NULL or in the future.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct InviteCodeRow {
    pub id: String,
    /// SHA-256 hex hash of the plaintext code. UNIQUE.
    pub code_hash: String,
    /// User id of the admin who created the code.
    pub created_by: String,
    pub created_at: TimestampMs,
    /// Absolute expiry (Unix ms); NULL means the code never expires.
    pub expires_at: Option<TimestampMs>,
    /// User id of the account that redeemed the code; NULL until used.
    pub used_by: Option<String>,
    pub used_at: Option<TimestampMs>,
    /// Set when an admin revokes the code; revoked codes are never redeemable.
    pub revoked_at: Option<TimestampMs>,
}
