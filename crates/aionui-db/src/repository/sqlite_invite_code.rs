use aionui_common::TimestampMs;
use sqlx::SqlitePool;

use crate::error::DbError;
use crate::models::InviteCodeRow;
use crate::repository::IInviteCodeRepository;

/// SQLite-backed implementation of [`IInviteCodeRepository`].
#[derive(Clone, Debug)]
pub struct SqliteInviteCodeRepository {
    pool: SqlitePool,
}

impl SqliteInviteCodeRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl IInviteCodeRepository for SqliteInviteCodeRepository {
    async fn create(&self, row: &InviteCodeRow) -> Result<(), DbError> {
        sqlx::query(
            "INSERT INTO invite_codes (id, code_hash, created_by, created_at, expires_at, used_by, used_at, revoked_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&row.id)
        .bind(&row.code_hash)
        .bind(&row.created_by)
        .bind(row.created_at)
        .bind(row.expires_at)
        .bind(&row.used_by)
        .bind(row.used_at)
        .bind(row.revoked_at)
        .execute(&self.pool)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db_err) if is_unique_violation(db_err.as_ref()) => {
                DbError::Conflict("Invite code already exists".to_string())
            }
            _ => DbError::Query(e),
        })?;

        Ok(())
    }

    async fn find_by_code_hash(&self, code_hash: &str) -> Result<Option<InviteCodeRow>, DbError> {
        let row = sqlx::query_as::<_, InviteCodeRow>("SELECT * FROM invite_codes WHERE code_hash = ?")
            .bind(code_hash)
            .fetch_optional(&self.pool)
            .await?;

        Ok(row)
    }

    async fn mark_used(&self, id: &str, used_by: &str, used_at: TimestampMs) -> Result<(), DbError> {
        // The WHERE clause is the redemption guard: a code that was used or
        // revoked between validation and this update matches zero rows, so a
        // code can never be redeemed twice even under a race.
        let result = sqlx::query(
            "UPDATE invite_codes SET used_by = ?, used_at = ? \
             WHERE id = ? AND used_by IS NULL AND revoked_at IS NULL",
        )
        .bind(used_by)
        .bind(used_at)
        .bind(id)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(DbError::Conflict("Invite code is no longer redeemable".to_string()));
        }

        Ok(())
    }

    async fn revoke(&self, id: &str, revoked_at: TimestampMs) -> Result<(), DbError> {
        let result = sqlx::query("UPDATE invite_codes SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL")
            .bind(revoked_at)
            .bind(id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            // Either unknown id, or already revoked (idempotent no-op case).
            let exists: Option<i64> = sqlx::query_scalar("SELECT 1 FROM invite_codes WHERE id = ?")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;
            if exists.is_none() {
                return Err(DbError::NotFound(format!("Invite code '{id}' not found")));
            }
        }

        Ok(())
    }

    async fn list(&self) -> Result<Vec<InviteCodeRow>, DbError> {
        let rows = sqlx::query_as::<_, InviteCodeRow>("SELECT * FROM invite_codes ORDER BY created_at DESC, id ASC")
            .fetch_all(&self.pool)
            .await?;

        Ok(rows)
    }
}

/// Detect SQLite UNIQUE constraint violation (codes 2067 / 1555).
fn is_unique_violation(err: &dyn sqlx::error::DatabaseError) -> bool {
    err.code().is_some_and(|c| c == "2067" || c == "1555")
}

#[cfg(test)]
#[path = "sqlite_invite_code_test.rs"]
mod sqlite_invite_code_test;
