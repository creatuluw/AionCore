//! Admin API contracts for multi-user management (`/api/admin/*`).
//!
//! All routes in this module require an authenticated `admin` user.

use serde::{Deserialize, Serialize};

use crate::auth::UserRole;

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

/// Admin view of a user account for `GET /api/admin/users`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AdminUserResponse {
    pub id: String,
    pub username: Option<String>,
    pub user_type: String,
    pub role: UserRole,
    pub status: String,
    pub session_generation: i64,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_login: Option<i64>,
}

/// Request body for `POST /api/admin/users` (create an account directly).
///
/// `role` defaults to `member` when omitted.
#[derive(Debug, Deserialize)]
pub struct AdminCreateUserRequest {
    pub username: String,
    pub password: String,
    pub role: Option<UserRole>,
}

/// Request body for `POST /api/admin/users/{id}/set-role`.
#[derive(Debug, Deserialize)]
pub struct SetRoleRequest {
    pub role: UserRole,
}

/// Request body for `POST /api/admin/users/{id}/set-password`.
#[derive(Debug, Deserialize)]
pub struct AdminSetPasswordRequest {
    pub password: String,
}

/// Response for account mutations (`set-role`, `set-password`, `disable`,
/// `enable`) — the updated admin view of the affected account.
pub type AdminUserMutationResponse = AdminUserResponse;

// ---------------------------------------------------------------------------
// Invite codes
// ---------------------------------------------------------------------------

/// Admin view of an invite code for `GET /api/admin/invites`.
///
/// Deliberately carries no `code_hash`: hashes never leave the server.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AdminInviteResponse {
    pub id: String,
    pub created_by: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub used_by: Option<String>,
    pub used_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

/// Request body for `POST /api/admin/invites`.
///
/// `expires_in_hours` is relative to creation time; `None` means the code
/// never expires.
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CreateInviteRequest {
    pub expires_in_hours: Option<i64>,
}

/// Response for `POST /api/admin/invites`.
///
/// `code` is the plaintext invite code — the ONLY time the server returns it;
/// only its SHA-256 hash is stored.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateInviteResponse {
    pub id: String,
    pub code: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
}

// ---------------------------------------------------------------------------
// Shared-key pool settings
// ---------------------------------------------------------------------------

/// Response for `GET /api/admin/pool-settings`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PoolSettingsResponse {
    pub shared_key_service_enabled: bool,
    pub shared_pool_daily_request_cap: i64,
}

/// Request body for `PUT /api/admin/pool-settings`.
pub type UpdatePoolSettingsRequest = PoolSettingsResponse;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_invite_response_uses_camel_case() {
        let invite = AdminInviteResponse {
            id: "invite_1".into(),
            created_by: "system_default_user".into(),
            created_at: 1700000000000,
            expires_at: Some(1700003600000),
            used_by: None,
            used_at: None,
            revoked_at: None,
        };
        let json = serde_json::to_value(&invite).unwrap();
        assert!(json.get("createdBy").is_some());
        assert!(json.get("expiresAt").is_some());
        assert!(json.get("created_by").is_none());
    }

    #[test]
    fn pool_settings_round_trips_camel_case() {
        let raw = r#"{"sharedKeyServiceEnabled":true,"sharedPoolDailyRequestCap":250}"#;
        let req: UpdatePoolSettingsRequest = serde_json::from_str(raw).unwrap();
        assert!(req.shared_key_service_enabled);
        assert_eq!(req.shared_pool_daily_request_cap, 250);

        let json = serde_json::to_value(req).unwrap();
        assert!(json.get("sharedKeyServiceEnabled").is_some());
    }

    #[test]
    fn role_deserializes_lowercase() {
        let req: SetRoleRequest = serde_json::from_str(r#"{"role":"admin"}"#).unwrap();
        assert_eq!(req.role, UserRole::Admin);
        assert!(serde_json::from_str::<SetRoleRequest>(r#"{"role":"superuser"}"#).is_err());
    }
}
