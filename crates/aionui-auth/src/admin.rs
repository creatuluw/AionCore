#![allow(clippy::disallowed_types)]

//! Admin-only endpoints: user management, invite codes, shared-pool settings.
//!
//! Every route here requires an authenticated user whose role is `admin`
//! (enforced by [`require_admin`], layered between `auth_middleware` and the
//! handler by the composition layer). Business rules for account creation
//! and passwords are delegated to [`crate::account`] and
//! [`crate::invite`], so CLI and HTTP entry points stay behaviorally
//! identical.

use std::sync::Arc;

use axum::extract::Request;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;
use axum::routing::{delete, get, post};
use axum::{Json, Router};

use aionui_api_types::{
    AdminCreateUserRequest, AdminInviteResponse, AdminSetPasswordRequest, AdminUserResponse, ApiResponse,
    CreateInviteRequest, CreateInviteResponse, PoolSettingsResponse, SetRoleRequest, UpdatePoolSettingsRequest,
    UserRole,
};
use aionui_common::ApiError;
use aionui_db::models::User;
use aionui_db::{IGlobalSettingsRepository, IInviteCodeRepository, IUserRepository, UserRole as DbUserRole};

use crate::account::create_local_user;
use crate::invite::{InviteError, create_invite, revoke_invite};
use crate::middleware::CurrentUser;
use crate::routes::SessionRevokedHook;
use crate::validation::validate_password;

/// Shared state for the admin route handlers.
#[derive(Clone)]
pub struct AdminRouterState {
    pub user_repo: Arc<dyn IUserRepository>,
    pub invite_repo: Arc<dyn IInviteCodeRepository>,
    pub settings_repo: Arc<dyn IGlobalSettingsRepository>,
    /// Fired after a successful `active → disabled` transition so live
    /// sessions and per-user runtimes are torn down, matching the
    /// session-revocation cleanup of the password/refresh flows.
    pub session_revoked_hook: Option<Arc<SessionRevokedHook>>,
}

/// Build the admin router. Bare routes only — the composition layer wraps
/// this with the auth middleware, `require_admin`, and rate limiters (see
/// `create_router_with_all_state`), so the middleware order for a request is:
/// api limiter → auth → `require_admin` → action limiter → handler.
pub fn admin_routes(state: AdminRouterState) -> Router {
    Router::new()
        .route("/api/admin/users", get(list_users_handler).post(create_user_handler))
        .route("/api/admin/users/{id}/set-role", post(set_role_handler))
        .route("/api/admin/users/{id}/disable", post(disable_user_handler))
        .route("/api/admin/users/{id}/enable", post(enable_user_handler))
        .route("/api/admin/users/{id}/set-password", post(set_password_handler))
        .route(
            "/api/admin/invites",
            get(list_invites_handler).post(create_invite_handler),
        )
        .route("/api/admin/invites/{id}", delete(revoke_invite_handler))
        .route(
            "/api/admin/pool-settings",
            get(get_pool_settings_handler).put(put_pool_settings_handler),
        )
        .with_state(state)
}

/// Gate admin routes: reject any authenticated user whose role is not
/// `admin`.
///
/// Runs strictly after `auth_middleware` (which inserts [`CurrentUser`]), so
/// the extension is guaranteed to exist. Local mode passes automatically: the
/// auth middleware injects the fixed default user with the `admin` role.
pub async fn require_admin(request: Request, next: Next) -> Result<Response, ApiError> {
    let user = request
        .extensions()
        .get::<CurrentUser>()
        .ok_or_else(|| ApiError::Unauthorized("Authentication required".into()))?;

    if user.role != UserRole::Admin {
        return Err(ApiError::coded(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "Admin privileges required.",
            None,
        ));
    }

    Ok(next.run(request).await)
}

fn admin_user_response(user: User) -> AdminUserResponse {
    AdminUserResponse {
        id: user.id,
        username: user.username,
        user_type: user.user_type.as_str().to_owned(),
        role: match user.role {
            DbUserRole::Admin => UserRole::Admin,
            DbUserRole::Member => UserRole::Member,
        },
        status: user.status.as_str().to_owned(),
        session_generation: user.session_generation,
        created_at: user.created_at,
        updated_at: user.updated_at,
        last_login: user.last_login,
    }
}

fn invite_error_to_api_error(err: InviteError) -> ApiError {
    match err {
        InviteError::NotRedeemable => ApiError::coded(
            StatusCode::BAD_REQUEST,
            "INVALID_INVITE",
            "Invite code is invalid, expired, or already used.",
            None,
        ),
        InviteError::InvalidExpiry => ApiError::BadRequest("expires_in_hours must be between 1 and 8760".into()),
        InviteError::Db(e) => match e {
            aionui_db::DbError::NotFound(msg) => ApiError::NotFound(msg),
            other => ApiError::Internal(format!("Database error: {other}")),
        },
    }
}

async fn load_user_or_404(state: &AdminRouterState, id: &str) -> Result<User, ApiError> {
    state
        .user_repo
        .find_by_id(id)
        .await
        .map_err(|e| ApiError::Internal(format!("Database error: {e}")))?
        .ok_or_else(|| ApiError::NotFound("User not found".into()))
}

async fn list_users_handler(
    State(state): State<AdminRouterState>,
) -> Result<Json<ApiResponse<Vec<AdminUserResponse>>>, ApiError> {
    let users = state
        .user_repo
        .list_users()
        .await
        .map_err(|e| ApiError::Internal(format!("Database error: {e}")))?;
    Ok(Json(ApiResponse::ok(
        users.into_iter().map(admin_user_response).collect(),
    )))
}

async fn create_user_handler(
    State(state): State<AdminRouterState>,
    body: Result<Json<AdminCreateUserRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<(StatusCode, Json<ApiResponse<AdminUserResponse>>), ApiError> {
    let Json(req) = body.map_err(ApiError::from)?;
    let role = req.role.unwrap_or(UserRole::Member);

    // `create_local_user` validates username + password and hashes with
    // bcrypt — the exact same rules the CLI `user create` path applies.
    let user_repo = state.user_repo.clone();
    let outcome = create_local_user(user_repo.as_ref(), &req.username, &req.password)
        .await
        .map_err(|e| match e {
            crate::account::AccountError::AlreadyExists(_) => ApiError::coded(
                StatusCode::CONFLICT,
                "USERNAME_TAKEN",
                "A user with this username already exists.",
                None,
            ),
            crate::account::AccountError::InvalidUsername(msg) => ApiError::BadRequest(msg),
            crate::account::AccountError::WeakPassword(msg) => ApiError::BadRequest(msg),
            crate::account::AccountError::Hash => ApiError::Internal("Password hash error".into()),
            crate::account::AccountError::Db(e) => ApiError::Internal(format!("Database error: {e}")),
        })?;

    let user_id = match &outcome {
        crate::account::PasswordOutcome::Created { id, .. } => id.clone(),
        other => {
            return Err(ApiError::Internal(format!("Unexpected account outcome: {other:?}")));
        }
    };

    if role == UserRole::Admin {
        state
            .user_repo
            .update_role(&user_id, DbUserRole::Admin)
            .await
            .map_err(|e| ApiError::Internal(format!("Database error: {e}")))?;
    }

    let user = load_user_or_404(&state, &user_id).await?;
    Ok((StatusCode::CREATED, Json(ApiResponse::ok(admin_user_response(user)))))
}

async fn set_role_handler(
    State(state): State<AdminRouterState>,
    Path(id): Path<String>,
    body: Result<Json<SetRoleRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<ApiResponse<AdminUserResponse>>, ApiError> {
    let Json(req) = body.map_err(ApiError::from)?;
    load_user_or_404(&state, &id).await?;

    let db_role = match req.role {
        UserRole::Admin => DbUserRole::Admin,
        UserRole::Member => DbUserRole::Member,
    };
    state
        .user_repo
        .update_role(&id, db_role)
        .await
        .map_err(|e| ApiError::Internal(format!("Database error: {e}")))?;

    let user = load_user_or_404(&state, &id).await?;
    Ok(Json(ApiResponse::ok(admin_user_response(user))))
}

/// Shared body of `disable` / `enable`: flip status, fire the revocation
/// hook on the active→disabled transition, return the updated account.
async fn set_user_status(
    state: &AdminRouterState,
    id: &str,
    status: aionui_db::UserStatus,
) -> Result<Json<ApiResponse<AdminUserResponse>>, ApiError> {
    let existing = load_user_or_404(state, id).await?;
    let was_active = existing.status == aionui_db::UserStatus::Active;

    state
        .user_repo
        .set_status(id, status)
        .await
        .map_err(|e| ApiError::Internal(format!("Database error: {e}")))?;

    if was_active && status == aionui_db::UserStatus::Disabled {
        // Parity with the password-change/refresh revocation flows: drop the
        // user's live WebSockets and per-user runtimes immediately instead of
        // waiting for their next request to bounce off the auth middleware.
        if let Some(hook) = &state.session_revoked_hook {
            hook(id);
        }
    }

    let user = load_user_or_404(state, id).await?;
    Ok(Json(ApiResponse::ok(admin_user_response(user))))
}

async fn disable_user_handler(
    State(state): State<AdminRouterState>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<AdminUserResponse>>, ApiError> {
    set_user_status(&state, &id, aionui_db::UserStatus::Disabled).await
}

async fn enable_user_handler(
    State(state): State<AdminRouterState>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<AdminUserResponse>>, ApiError> {
    set_user_status(&state, &id, aionui_db::UserStatus::Active).await
}

async fn set_password_handler(
    State(state): State<AdminRouterState>,
    Path(id): Path<String>,
    body: Result<Json<AdminSetPasswordRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<ApiResponse<AdminUserResponse>>, ApiError> {
    let Json(req) = body.map_err(ApiError::from)?;
    validate_password(&req.password).map_err(|e| ApiError::BadRequest(e.to_string()))?;
    load_user_or_404(&state, &id).await?;

    // Same hashing as the change-password flow (bcrypt on a blocking thread,
    // off the async reactor). Does NOT bump session_generation, mirroring the
    // CLI `user set-password` semantics.
    let password = req.password.clone();
    let hash = tokio::task::spawn_blocking(move || crate::password::hash_password(&password))
        .await
        .map_err(|e| ApiError::Internal(format!("Task join error: {e}")))?
        .map_err(|_| ApiError::Internal("Password hash error".into()))?;
    state
        .user_repo
        .update_password(&id, &hash)
        .await
        .map_err(|e| ApiError::Internal(format!("Database error: {e}")))?;

    let user = load_user_or_404(&state, &id).await?;
    Ok(Json(ApiResponse::ok(admin_user_response(user))))
}

async fn list_invites_handler(
    State(state): State<AdminRouterState>,
) -> Result<Json<ApiResponse<Vec<AdminInviteResponse>>>, ApiError> {
    let invites = state
        .invite_repo
        .list()
        .await
        .map_err(|e| ApiError::Internal(format!("Database error: {e}")))?;
    Ok(Json(ApiResponse::ok(
        invites
            .into_iter()
            .map(|invite| AdminInviteResponse {
                id: invite.id,
                created_by: invite.created_by,
                created_at: invite.created_at,
                expires_at: invite.expires_at,
                used_by: invite.used_by,
                used_at: invite.used_at,
                revoked_at: invite.revoked_at,
            })
            .collect(),
    )))
}

async fn create_invite_handler(
    State(state): State<AdminRouterState>,
    creator: axum::Extension<CurrentUser>,
    body: Result<Json<CreateInviteRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<(StatusCode, Json<ApiResponse<CreateInviteResponse>>), ApiError> {
    let Json(req) = body.map_err(ApiError::from)?;

    let created = create_invite(state.invite_repo.as_ref(), &creator.id, req.expires_in_hours)
        .await
        .map_err(invite_error_to_api_error)?;

    Ok((
        StatusCode::CREATED,
        Json(ApiResponse::ok(CreateInviteResponse {
            id: created.invite.id,
            // The plaintext is shown exactly once — only its hash is stored.
            code: created.plaintext_code,
            created_at: created.invite.created_at,
            expires_at: created.invite.expires_at,
        })),
    ))
}

async fn revoke_invite_handler(
    State(state): State<AdminRouterState>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    revoke_invite(state.invite_repo.as_ref(), &id)
        .await
        .map_err(invite_error_to_api_error)?;
    Ok(Json(ApiResponse::message("Invite code revoked")))
}

async fn get_pool_settings_handler(
    State(state): State<AdminRouterState>,
) -> Result<Json<ApiResponse<PoolSettingsResponse>>, ApiError> {
    let settings = state
        .settings_repo
        .get()
        .await
        .map_err(|e| ApiError::Internal(format!("Database error: {e}")))?;
    Ok(Json(ApiResponse::ok(PoolSettingsResponse {
        shared_key_service_enabled: settings.shared_key_service_enabled,
        shared_pool_daily_request_cap: settings.shared_pool_daily_request_cap,
    })))
}

async fn put_pool_settings_handler(
    State(state): State<AdminRouterState>,
    body: Result<Json<UpdatePoolSettingsRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<ApiResponse<PoolSettingsResponse>>, ApiError> {
    let Json(req) = body.map_err(ApiError::from)?;

    if req.shared_pool_daily_request_cap < 0 {
        return Err(ApiError::BadRequest(
            "shared_pool_daily_request_cap must not be negative".into(),
        ));
    }

    let settings = aionui_db::GlobalSettings {
        shared_key_service_enabled: req.shared_key_service_enabled,
        shared_pool_daily_request_cap: req.shared_pool_daily_request_cap,
    };
    state
        .settings_repo
        .upsert(&settings)
        .await
        .map_err(|e| ApiError::Internal(format!("Database error: {e}")))?;

    Ok(Json(ApiResponse::ok(req)))
}
