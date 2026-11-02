//! Invite-code creation and redemption.
//!
//! An invite code is a random URL-safe base62 string (>= 128 bits of entropy).
//! Only its SHA-256 hex hash is stored; the plaintext is returned to the
//! creating admin exactly once and never persisted. Redemption validates the
//! hash against the stored row and enforces un-revoked / un-expired / unused.
//!
//! Free functions over repository traits, mirroring the [`crate::account`]
//! pattern: the HTTP handlers and CLI adapters translate I/O around this
//! module, which owns all invite business rules.

use sha2::{Digest, Sha256};

use aionui_common::now_ms;
use aionui_db::{IInviteCodeRepository, InviteCodeRow};

/// Length of a generated invite code in base62 characters.
///
/// 24 chars × log2(62) ≈ 142.9 bits of entropy — comfortably above the
/// 128-bit floor, and short enough to read out over a video call.
pub const INVITE_CODE_LENGTH: usize = 24;

/// URL-safe base62 alphabet (digits, lowercase, uppercase — in that order).
const BASE62_ALPHABET: &[u8; 62] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// Rejection-sampling ceiling: the largest multiple of 62 that fits a byte.
/// Bytes at or above it are discarded so `byte % 62` stays uniform.
const SAMPLING_CEILING: u8 = 248;

/// Errors from invite creation and redemption.
#[derive(Debug, thiserror::Error)]
pub enum InviteError {
    /// Code does not exist, is revoked, is expired, or was already used.
    /// One variant (not four) so responses cannot distinguish between them
    /// and leak code state to unauthenticated callers.
    #[error("invite code is invalid, expired, or already used")]
    NotRedeemable,
    /// `expires_in_hours` was out of the acceptable range.
    #[error("expires_in_hours must be between 1 and 8760")]
    InvalidExpiry,
    #[error("database error: {0}")]
    Db(#[from] aionui_db::DbError),
}

/// Generate a random invite code: `INVITE_CODE_LENGTH` URL-safe base62
/// characters drawn from OS entropy with rejection sampling (no modulo bias).
pub fn generate_invite_code() -> String {
    use std::fmt::Write as _;

    let mut code = String::with_capacity(INVITE_CODE_LENGTH);
    let mut buf = [0u8; 64];
    while code.len() < INVITE_CODE_LENGTH {
        getrandom::getrandom(&mut buf).expect("OS entropy source unavailable");
        for &byte in buf.iter() {
            if byte < SAMPLING_CEILING && code.len() < INVITE_CODE_LENGTH {
                let _ = write!(code, "{}", BASE62_ALPHABET[(byte % 62) as usize] as char);
            }
        }
    }
    code
}

/// Hash a plaintext invite code to the stored form (lowercase SHA-256 hex).
pub fn hash_invite_code(code: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(code.as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    use std::fmt::Write as _;
    for byte in digest {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// A freshly created invite: the row that was persisted plus the plaintext
/// code, which the caller must show to the admin exactly once.
#[derive(Debug, Clone)]
pub struct CreatedInvite {
    pub invite: InviteCodeRow,
    pub plaintext_code: String,
}

/// Create a new invite code on behalf of `created_by`.
///
/// `expires_in_hours` is relative to now; `None` means the code never
/// expires. Returns the plaintext code once — only the hash is stored.
pub async fn create_invite(
    repo: &dyn IInviteCodeRepository,
    created_by: &str,
    expires_in_hours: Option<i64>,
) -> Result<CreatedInvite, InviteError> {
    let expires_at = match expires_in_hours {
        None => None,
        Some(hours) => {
            // Reject absurd values (negative, zero, > 1 year) up front so a
            // fat-fingered admin cannot create a permanently-live or
            // already-dead code by accident.
            if !(1..=24 * 365).contains(&hours) {
                return Err(InviteError::InvalidExpiry);
            }
            Some(now_ms() + hours * 60 * 60 * 1000)
        }
    };

    let plaintext_code = generate_invite_code();
    let invite = InviteCodeRow {
        id: aionui_common::generate_prefixed_id("invite"),
        code_hash: hash_invite_code(&plaintext_code),
        created_by: created_by.to_owned(),
        created_at: now_ms(),
        expires_at,
        used_by: None,
        used_at: None,
        revoked_at: None,
    };
    repo.create(&invite).await?;

    // Non-sensitive: logs the invite id and expiry, never the code or hash.
    tracing::info!(invite_id = %invite.id, created_by = created_by, expires_at = ?expires_at, "invite code created");
    Ok(CreatedInvite { invite, plaintext_code })
}

/// Validate a plaintext invite code for redemption.
///
/// Checks, in order: the hash exists, the code is not revoked, not expired,
/// and not already used. Any failure maps to [`InviteError::NotRedeemable`]
/// so callers cannot learn WHY a code failed.
///
/// Redemption is not finalized here — the caller creates the account first,
/// then calls [`mark_invite_used`]; `mark_used`'s WHERE guard closes the
/// double-redemption race.
pub async fn redeem_validate(
    repo: &dyn IInviteCodeRepository,
    plaintext_code: &str,
) -> Result<InviteCodeRow, InviteError> {
    let invite = repo
        .find_by_code_hash(&hash_invite_code(plaintext_code))
        .await?
        .ok_or(InviteError::NotRedeemable)?;

    if invite.revoked_at.is_some() || invite.used_by.is_some() {
        return Err(InviteError::NotRedeemable);
    }
    if invite.expires_at.is_some_and(|expires_at| now_ms() >= expires_at) {
        return Err(InviteError::NotRedeemable);
    }
    Ok(invite)
}

/// Finalize redemption: mark the code used by `user_id`.
///
/// Fails with `InviteError::NotRedeemable` if the code was consumed or
/// revoked concurrently (the repository update matches zero rows).
pub async fn mark_invite_used(
    repo: &dyn IInviteCodeRepository,
    invite_id: &str,
    user_id: &str,
) -> Result<(), InviteError> {
    repo.mark_used(invite_id, user_id, now_ms())
        .await
        .map_err(|_| InviteError::NotRedeemable)?;
    tracing::info!(invite_id = invite_id, "invite code redeemed");
    Ok(())
}

/// Revoke an invite code (admin action). Idempotent for already-revoked codes.
pub async fn revoke_invite(repo: &dyn IInviteCodeRepository, invite_id: &str) -> Result<(), InviteError> {
    repo.revoke(invite_id, now_ms()).await?;
    tracing::info!(invite_id = invite_id, "invite code revoked");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_codes_have_expected_length_and_alphabet() {
        for _ in 0..32 {
            let code = generate_invite_code();
            assert_eq!(code.len(), INVITE_CODE_LENGTH);
            assert!(
                code.bytes().all(|b| BASE62_ALPHABET.contains(&b)),
                "code must be base62 only: {code}"
            );
        }
    }

    #[test]
    fn generated_codes_are_distinct() {
        let codes: std::collections::HashSet<String> = (0..64).map(|_| generate_invite_code()).collect();
        assert_eq!(codes.len(), 64, "OS-entropy codes must not collide");
    }

    #[test]
    fn hash_is_deterministic_and_hex() {
        let a = hash_invite_code("some-code");
        let b = hash_invite_code("some-code");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        assert!(a.bytes().all(|b| b.is_ascii_hexdigit()));
        // Case sensitivity: different inputs, different hashes.
        assert_ne!(hash_invite_code("Some-Code"), a);
    }

    #[test]
    fn generated_code_hashes_do_not_contain_the_plaintext() {
        let code = generate_invite_code();
        let hash = hash_invite_code(&code);
        assert!(!hash.contains(&code), "stored hash must not leak the plaintext");
    }
}
