//! End-to-end tests for multi-user accounts: invite-gated registration,
//! role enforcement on admin routes, admin user/invite management, and
//! shared-pool settings.
//!
//! Follows the `common::setup_and_login` pattern: full HTTP stack over an
//! in-memory SQLite database (`WebUi` identity mode, so CSRF is active).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use aionui_app::AppServices;

use common::{
    body_json, build_app, delete_with_token, get_request, get_with_token, json_with_token, post_json, setup_and_login,
};

mod common;

fn register_request(code: &str, username: &str, password: &str) -> Request<Body> {
    let body = serde_json::json!({ "code": code, "username": username, "password": password });
    Request::builder()
        .method("POST")
        .uri("/api/auth/register")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

/// Create an invite through the admin API, returning (id, plaintext code).
async fn create_invite_via_api(
    app: &axum::Router,
    token: &str,
    csrf: &str,
    expires_in_hours: Option<i64>,
) -> (String, String) {
    let body = match expires_in_hours {
        Some(h) => serde_json::json!({ "expiresInHours": h }),
        None => serde_json::json!({}),
    };
    let resp = app
        .clone()
        .oneshot(json_with_token("POST", "/api/admin/invites", body, token, csrf))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "invite creation should succeed");
    let json = body_json(resp).await;
    let id = json["data"]["id"].as_str().unwrap().to_owned();
    let code = json["data"]["code"].as_str().unwrap().to_owned();
    (id, code)
}

/// Register a user through the public endpoint and assert success.
/// Returns the new user's id and session token.
async fn register_ok(app: &axum::Router, code: &str, username: &str, password: &str) -> (String, String) {
    let resp = app
        .clone()
        .oneshot(register_request(code, username, password))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "registration should succeed");
    let json = body_json(resp).await;
    (
        json["user"]["id"].as_str().unwrap().to_owned(),
        json["token"].as_str().unwrap().to_owned(),
    )
}

/// Admin test context: app + admin credentials.
async fn admin_app() -> (axum::Router, AppServices, String, String) {
    let (mut app, services) = build_app().await;
    let (token, csrf) = setup_and_login(&mut app, &services, "admin", "admin-pass-1").await;
    (app, services, token, csrf)
}

// ---------------------------------------------------------------------------
// Registration via invite
// ---------------------------------------------------------------------------

#[tokio::test]
async fn register_via_invite_happy_path_then_can_list_conversations() {
    let (app, _services, admin_token, admin_csrf) = admin_app().await;
    let (_invite_id, code) = create_invite_via_api(&app, &admin_token, &admin_csrf, None).await;

    let (user_id, token) = register_ok(&app, &code, "invited", "invitee-pass-1").await;
    assert!(
        user_id.starts_with("user_"),
        "new user id should be prefixed: {user_id}"
    );

    // The fresh session token works on ordinary user routes.
    let resp = app
        .clone()
        .oneshot(get_with_token("/api/conversations", &token))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "registered member can list conversations"
    );

    // The new account is a member, visible in the admin listing.
    let resp = app
        .clone()
        .oneshot(get_with_token("/api/admin/users", &admin_token))
        .await
        .unwrap();
    let json = body_json(resp).await;
    let users = json["data"].as_array().unwrap();
    let invited = users.iter().find(|u| u["id"] == user_id.as_str()).unwrap();
    assert_eq!(invited["role"], "member");
    assert_eq!(invited["username"], "invited");
    assert_eq!(invited["status"], "active");
}

#[tokio::test]
async fn register_with_unknown_code_rejected_with_invalid_invite() {
    let (app, _services, _t, _c) = admin_app().await;

    let resp = app
        .clone()
        .oneshot(register_request(
            "totally-bogus-code-123456",
            "newcomer",
            "good-pass-123",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = body_json(resp).await;
    assert_eq!(json["code"], "INVALID_INVITE");
}

#[tokio::test]
async fn register_with_used_code_rejected() {
    let (app, _services, admin_token, admin_csrf) = admin_app().await;
    let (_id, code) = create_invite_via_api(&app, &admin_token, &admin_csrf, None).await;

    let (_uid, _tok) = register_ok(&app, &code, "first-user", "first-pass-123").await;

    // Same code, second registration → 400 INVALID_INVITE (no detail leak).
    let resp = app
        .clone()
        .oneshot(register_request(&code, "second-user", "second-pass-123"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = body_json(resp).await;
    assert_eq!(json["code"], "INVALID_INVITE");
}

#[tokio::test]
async fn register_with_expired_code_rejected() {
    let (app, services, _t, _c) = admin_app().await;

    // Seed an already-expired invite directly via the repository.
    let plaintext = aionui_auth::generate_invite_code();
    let row = aionui_db::InviteCodeRow {
        id: "invite_expired_test".to_owned(),
        code_hash: aionui_auth::hash_invite_code(&plaintext),
        created_by: "system_default_user".to_owned(),
        created_at: aionui_common::now_ms() - 3_600_000,
        expires_at: Some(aionui_common::now_ms() - 60_000),
        used_by: None,
        used_at: None,
        revoked_at: None,
    };
    services.invite_repo.create(&row).await.unwrap();

    let resp = app
        .clone()
        .oneshot(register_request(&plaintext, "late-user", "late-pass-1234"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = body_json(resp).await;
    assert_eq!(json["code"], "INVALID_INVITE");
}

#[tokio::test]
async fn register_with_weak_password_rejected() {
    let (app, _services, admin_token, admin_csrf) = admin_app().await;
    let (_id, code) = create_invite_via_api(&app, &admin_token, &admin_csrf, None).await;

    let resp = app
        .clone()
        .oneshot(register_request(&code, "weak-pass-user", "password"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Bad-path specificity: the password rejection (not the invite) caused it.
    let json = body_json(resp).await;
    assert!(
        json["error"].as_str().unwrap().to_lowercase().contains("password"),
        "error should mention the password: {}",
        json["error"]
    );
}

#[tokio::test]
async fn register_with_taken_username_conflicts() {
    let (app, _services, admin_token, admin_csrf) = admin_app().await;
    let (_id, code) = create_invite_via_api(&app, &admin_token, &admin_csrf, None).await;

    let resp = app
        .clone()
        .oneshot(register_request(&code, "admin", "another-pass-1"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let json = body_json(resp).await;
    assert_eq!(json["code"], "USERNAME_TAKEN");
}

#[tokio::test]
async fn register_with_invalid_username_rejected() {
    let (app, _services, admin_token, admin_csrf) = admin_app().await;
    let (_id, code) = create_invite_via_api(&app, &admin_token, &admin_csrf, None).await;

    let resp = app
        .clone()
        .oneshot(register_request(&code, "ab", "good-pass-123"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// Role enforcement on admin routes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn member_hitting_admin_routes_is_forbidden() {
    let (app, _services, admin_token, admin_csrf) = admin_app().await;
    let (_id, code) = create_invite_via_api(&app, &admin_token, &admin_csrf, None).await;
    let (_uid, member_token) = register_ok(&app, &code, "plain-member", "member-pass-1").await;

    for (method, uri, body) in [
        ("GET", "/api/admin/users", None),
        ("POST", "/api/admin/invites", Some(serde_json::json!({}))),
        ("GET", "/api/admin/pool-settings", None),
    ] {
        let req = match body {
            Some(b) => json_with_token(method, uri, b, &member_token, "unused-csrf"),
            None => get_with_token(uri, &member_token),
        };
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "{method} {uri} must be forbidden for members"
        );
        if method == "GET" {
            let json = body_json(resp).await;
            assert_eq!(json["code"], "FORBIDDEN");
        }
    }
}

#[tokio::test]
async fn unauthenticated_admin_access_is_unauthorized() {
    let (app, _services, _t, _c) = admin_app().await;

    let resp = app.clone().oneshot(get_request("/api/admin/users")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// Admin user management
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_lists_users_with_roles() {
    let (app, _services, admin_token, _csrf) = admin_app().await;

    let resp = app
        .clone()
        .oneshot(get_with_token("/api/admin/users", &admin_token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let users = json["data"].as_array().unwrap();
    let system = users.iter().find(|u| u["id"] == "system_default_user").unwrap();
    assert_eq!(system["role"], "admin", "seed admin must have the admin role");
    assert_eq!(system["username"], "admin");
    // Sensitive fields must never leak through the admin listing.
    assert!(system.get("password_hash").is_none());
    assert!(system.get("jwt_secret").is_none());
    assert!(system.get("encryption_secret").is_none());
}

#[tokio::test]
async fn admin_creates_user_with_default_and_explicit_role() {
    let (app, _services, admin_token, admin_csrf) = admin_app().await;

    // Default role = member.
    let resp = app
        .clone()
        .oneshot(json_with_token(
            "POST",
            "/api/admin/users",
            serde_json::json!({ "username": "created-member", "password": "created-pass-1" }),
            &admin_token,
            &admin_csrf,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let json = body_json(resp).await;
    assert_eq!(json["data"]["role"], "member");

    // Explicit role = admin.
    let resp = app
        .clone()
        .oneshot(json_with_token(
            "POST",
            "/api/admin/users",
            serde_json::json!({ "username": "created-admin", "password": "created-pass-2", "role": "admin" }),
            &admin_token,
            &admin_csrf,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let json = body_json(resp).await;
    assert_eq!(json["data"]["role"], "admin");

    // Duplicate username → 409 USERNAME_TAKEN.
    let resp = app
        .clone()
        .oneshot(json_with_token(
            "POST",
            "/api/admin/users",
            serde_json::json!({ "username": "created-member", "password": "created-pass-3" }),
            &admin_token,
            &admin_csrf,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let json = body_json(resp).await;
    assert_eq!(json["code"], "USERNAME_TAKEN");
}

#[tokio::test]
async fn admin_sets_role_and_new_admin_gains_admin_access() {
    let (app, _services, admin_token, admin_csrf) = admin_app().await;
    let (_id, code) = create_invite_via_api(&app, &admin_token, &admin_csrf, None).await;
    let (member_id, member_token) = register_ok(&app, &code, "promoted", "promote-pass-1").await;

    // Member cannot list invites.
    let resp = app
        .clone()
        .oneshot(get_with_token("/api/admin/invites", &member_token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Admin promotes the member.
    let resp = app
        .clone()
        .oneshot(json_with_token(
            "POST",
            &format!("/api/admin/users/{member_id}/set-role"),
            serde_json::json!({ "role": "admin" }),
            &admin_token,
            &admin_csrf,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["data"]["role"], "admin");

    // The role takes effect on the member's existing session.
    let resp = app
        .clone()
        .oneshot(get_with_token("/api/admin/invites", &member_token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Demote back; admin access disappears.
    let resp = app
        .clone()
        .oneshot(json_with_token(
            "POST",
            &format!("/api/admin/users/{member_id}/set-role"),
            serde_json::json!({ "role": "member" }),
            &admin_token,
            &admin_csrf,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = app
        .clone()
        .oneshot(get_with_token("/api/admin/invites", &member_token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Unknown user id → 404.
    let resp = app
        .clone()
        .oneshot(json_with_token(
            "POST",
            "/api/admin/users/no-such-user/set-role",
            serde_json::json!({ "role": "admin" }),
            &admin_token,
            &admin_csrf,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn admin_disables_user_and_existing_session_is_rejected() {
    let (app, _services, admin_token, admin_csrf) = admin_app().await;
    let (_id, code) = create_invite_via_api(&app, &admin_token, &admin_csrf, None).await;
    let (user_id, user_token) = register_ok(&app, &code, "to-disable", "disable-pass-1").await;

    // Session works before the disable.
    let resp = app
        .clone()
        .oneshot(get_with_token("/api/conversations", &user_token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Admin disables the account.
    let resp = app
        .clone()
        .oneshot(json_with_token(
            "POST",
            &format!("/api/admin/users/{user_id}/disable"),
            serde_json::json!({}),
            &admin_token,
            &admin_csrf,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["data"]["status"], "disabled");

    // The existing session is now rejected (auth middleware: user inactive).
    let resp = app
        .clone()
        .oneshot(get_with_token("/api/conversations", &user_token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // And login is refused.
    let resp = app
        .clone()
        .oneshot(post_json(
            "/login",
            &serde_json::json!({ "username": "to-disable", "password": "disable-pass-1" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Re-enable restores login.
    let resp = app
        .clone()
        .oneshot(json_with_token(
            "POST",
            &format!("/api/admin/users/{user_id}/enable"),
            serde_json::json!({}),
            &admin_token,
            &admin_csrf,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .clone()
        .oneshot(post_json(
            "/login",
            &serde_json::json!({ "username": "to-disable", "password": "disable-pass-1" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "re-enabled user can log in again");
}

#[tokio::test]
async fn admin_sets_password_and_old_password_stops_working() {
    let (app, _services, admin_token, admin_csrf) = admin_app().await;
    let (_id, code) = create_invite_via_api(&app, &admin_token, &admin_csrf, None).await;
    let (user_id, _tok) = register_ok(&app, &code, "pw-reset", "old-pass-1234").await;

    let resp = app
        .clone()
        .oneshot(json_with_token(
            "POST",
            &format!("/api/admin/users/{user_id}/set-password"),
            serde_json::json!({ "password": "new-pass-9999" }),
            &admin_token,
            &admin_csrf,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .clone()
        .oneshot(post_json(
            "/login",
            &serde_json::json!({ "username": "pw-reset", "password": "old-pass-1234" }),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "old password must stop working"
    );

    let resp = app
        .clone()
        .oneshot(post_json(
            "/login",
            &serde_json::json!({ "username": "pw-reset", "password": "new-pass-9999" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "new password must work");
}

// ---------------------------------------------------------------------------
// Admin invite management
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invite_plaintext_is_shown_once_and_never_listed() {
    let (app, _services, admin_token, admin_csrf) = admin_app().await;
    let (invite_id, code) = create_invite_via_api(&app, &admin_token, &admin_csrf, Some(24)).await;

    assert!(code.len() >= 24, "invite code should be >= 24 chars: {code}");
    assert!(
        code.bytes().all(|b| b.is_ascii_alphanumeric()),
        "invite code should be URL-safe base62: {code}"
    );

    // The listing shows state but never the code or its hash.
    let resp = app
        .clone()
        .oneshot(get_with_token("/api/admin/invites", &admin_token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let raw = serde_json::to_string(&json).unwrap();
    assert!(!raw.contains(&code), "plaintext code must never appear in listings");
    assert!(json["data"].as_array().unwrap()[0].get("codeHash").is_none());
    let invite = json["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["id"] == invite_id.as_str())
        .unwrap();
    assert_eq!(invite["createdBy"], "system_default_user");
    assert!(
        invite["expiresAt"].is_i64(),
        "expiry from expires_in_hours should be set"
    );

    // Revoke → redemption fails.
    let resp = app
        .clone()
        .oneshot(delete_with_token(
            &format!("/api/admin/invites/{invite_id}"),
            &admin_token,
            &admin_csrf,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .clone()
        .oneshot(register_request(&code, "revoked-user", "revoked-pass-1"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = body_json(resp).await;
    assert_eq!(json["code"], "INVALID_INVITE");

    // Revoking again is a no-op, not an error.
    let resp = app
        .clone()
        .oneshot(delete_with_token(
            &format!("/api/admin/invites/{invite_id}"),
            &admin_token,
            &admin_csrf,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Unknown invite id → 404.
    let resp = app
        .clone()
        .oneshot(delete_with_token(
            "/api/admin/invites/no-such-id",
            &admin_token,
            &admin_csrf,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Shared-pool settings
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pool_settings_roundtrip() {
    let (app, _services, admin_token, admin_csrf) = admin_app().await;

    // Defaults straight from the migration seed.
    let resp = app
        .clone()
        .oneshot(get_with_token("/api/admin/pool-settings", &admin_token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["data"]["sharedKeyServiceEnabled"], false);
    assert_eq!(json["data"]["sharedPoolDailyRequestCap"], 100);

    // Update.
    let resp = app
        .clone()
        .oneshot(json_with_token(
            "PUT",
            "/api/admin/pool-settings",
            serde_json::json!({ "sharedKeyServiceEnabled": true, "sharedPoolDailyRequestCap": 250 }),
            &admin_token,
            &admin_csrf,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Read back.
    let resp = app
        .clone()
        .oneshot(get_with_token("/api/admin/pool-settings", &admin_token))
        .await
        .unwrap();
    let json = body_json(resp).await;
    assert_eq!(json["data"]["sharedKeyServiceEnabled"], true);
    assert_eq!(json["data"]["sharedPoolDailyRequestCap"], 250);

    // Members cannot read or write.
    let (_id, code) = create_invite_via_api(&app, &admin_token, &admin_csrf, None).await;
    let (_uid, member_token) = register_ok(&app, &code, "pool-member", "pool-pass-123").await;
    let resp = app
        .clone()
        .oneshot(get_with_token("/api/admin/pool-settings", &member_token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ---------------------------------------------------------------------------
// Auth identity responses carry the role
// ---------------------------------------------------------------------------

#[tokio::test]
async fn auth_user_and_status_responses_include_role() {
    let (app, _services, _t, _c) = admin_app().await;

    // Login response contains the admin role.
    let resp = app
        .clone()
        .oneshot(post_json(
            "/login",
            &serde_json::json!({ "username": "admin", "password": "admin-pass-1" }),
        ))
        .await
        .unwrap();
    let json = body_json(resp).await;
    assert_eq!(json["user"]["role"], "admin", "login should report the admin role");
    let admin_token = json["token"].as_str().unwrap().to_owned();

    // /api/auth/user reports the role.
    let resp = app
        .clone()
        .oneshot(get_with_token("/api/auth/user", &admin_token))
        .await
        .unwrap();
    let json = body_json(resp).await;
    assert_eq!(json["user"]["role"], "admin");

    // /api/auth/status reports the role when a valid access token is present.
    let resp = app
        .clone()
        .oneshot(get_with_token("/api/auth/status", &admin_token))
        .await
        .unwrap();
    let json = body_json(resp).await;
    assert_eq!(json["role"], "admin");
    assert_eq!(json["is_authenticated"], true);

    // Without a token, is_authenticated is false and role is absent.
    let resp = app.clone().oneshot(get_request("/api/auth/status")).await.unwrap();
    let json = body_json(resp).await;
    assert_eq!(json["is_authenticated"], false);
    assert!(json.get("role").is_none(), "role must be omitted for anonymous status");
}
