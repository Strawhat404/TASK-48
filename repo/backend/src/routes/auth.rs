use crate::middleware::AuthenticatedUser;
use crate::models::auth::*;
use crate::models::user::UserResponse;
use crate::models;
use crate::DbPool;
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use rand::Rng;
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::State;
use uuid::Uuid;

fn generate_token(user_id: &str, username: &str, role: &str, session_id: &str) -> Result<String, Status> {
    let jwt_secret = std::env::var("JWT_SECRET")
        .expect("JWT_SECRET environment variable must be set");
    let expiry_hours: u64 = std::env::var("TOKEN_EXPIRY_HOURS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(24);

    let now = Utc::now().timestamp() as usize;
    let claims = Claims {
        sub: user_id.to_string(),
        username: username.to_string(),
        role: role.to_string(),
        iat: now,
        exp: now + (expiry_hours as usize * 3600),
        session_id: session_id.to_string(),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_bytes()),
    )
    .map_err(|e| { log::error!("generate_token: JWT encode failed: {}", e); Status::InternalServerError })
}

async fn create_session(pool: &DbPool, user_id: &str, token: &str) -> Result<String, Status> {
    let session_id = Uuid::new_v4().to_string();
    let now = Utc::now().naive_utc();
    let expires = now + Duration::minutes(models::SESSION_IDLE_TIMEOUT_MINUTES);

    sqlx::query(
        "INSERT INTO sessions (id, user_id, token, last_activity, expires_at, is_active) VALUES (?, ?, ?, ?, ?, true)"
    )
    .bind(&session_id)
    .bind(user_id)
    .bind(token)
    .bind(now)
    .bind(expires)
    .execute(pool)
    .await
    .map_err(|e| { log::error!("create_session: session insert failed: {}", e); Status::InternalServerError })?;

    Ok(session_id)
}

async fn log_audit(pool: &DbPool, user_id: Option<&str>, action: &str, target_type: Option<&str>, target_id: Option<&str>, details: Option<&str>) {
    let _ = sqlx::query(
        "INSERT INTO audit_log (id, user_id, action, target_type, target_id, details, created_at) VALUES (?, ?, ?, ?, ?, ?, NOW())"
    )
    .bind(Uuid::new_v4().to_string())
    .bind(user_id)
    .bind(action)
    .bind(target_type)
    .bind(target_id)
    .bind(details)
    .execute(pool)
    .await;
}

#[post("/login", data = "<req>")]
pub async fn login(pool: &State<DbPool>, req: Json<LoginRequest>) -> Result<Json<LoginResponse>, Status> {
    let row = sqlx::query_as::<_, (String, String, String, String, String, String, Option<String>, String, bool, Option<String>, bool, bool, bool, bool)>(
        "SELECT id, username, email, password_hash, first_name, last_name, contact_info, role, is_active, invoice_title, notify_submissions, notify_orders, notify_reviews, notify_cases FROM users WHERE username = ? AND is_active = true AND soft_deleted_at IS NULL"
    )
    .bind(&req.username)
    .fetch_optional(pool.inner())
    .await
    .map_err(|e| { log::error!("login: user query failed: {}", e); Status::InternalServerError })?;

    match row {
        Some((id, username, email, password_hash, first_name, last_name, contact_info, role, is_active, invoice_title, ns, no, nr, nc)) => {
            let password = req.password.clone();
            let hash_clone = password_hash.clone();
            let valid = tokio::task::spawn_blocking(move || {
                verify(&password, &hash_clone).unwrap_or(false)
            }).await.unwrap_or(false);
            if !valid {
                log_audit(pool.inner(), Some(&id), "login_failed", Some("user"), Some(&id), Some("Invalid password")).await;
                return Err(Status::Unauthorized);
            }

            // Create session
            let session_id = Uuid::new_v4().to_string();
            let token = generate_token(&id, &username, &role, &session_id)?;
            let now = Utc::now().naive_utc();
            let expires = now + Duration::minutes(models::SESSION_IDLE_TIMEOUT_MINUTES);

            sqlx::query(
                "INSERT INTO sessions (id, user_id, token, last_activity, expires_at, is_active) VALUES (?, ?, ?, ?, ?, true)"
            )
            .bind(&session_id)
            .bind(&id)
            .bind(&token)
            .bind(now)
            .bind(expires)
            .execute(pool.inner())
            .await
            .map_err(|e| { log::error!("login: session insert failed: {}", e); Status::InternalServerError })?;

            log_audit(pool.inner(), Some(&id), "login_success", Some("user"), Some(&id), None).await;

            Ok(Json(LoginResponse {
                token,
                user: UserResponse {
                    id, username, email, first_name, last_name, contact_info, role, is_active,
                    invoice_title, notify_submissions: ns, notify_orders: no, notify_reviews: nr,
                    notify_cases: nc, created_at: None,
                },
            }))
        }
        None => Err(Status::Unauthorized),
    }
}

/// Admin-provisioned account creation — no public self-registration.
#[post("/provision", data = "<req>")]
pub async fn register(pool: &State<DbPool>, admin: AuthenticatedUser, req: Json<crate::models::user::CreateUserRequest>) -> Result<Json<LoginResponse>, Status> {
    // Only administrators can provision new accounts
    admin.require_permission("admin.provision_users")?;

    let existing = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE email = ? OR username = ?")
        .bind(&req.email)
        .bind(&req.username)
        .fetch_one(pool.inner())
        .await
        .map_err(|e| { log::error!("register: duplicate check query failed: {}", e); Status::InternalServerError })?;

    if existing > 0 {
        return Err(Status::Conflict);
    }

    let valid_roles = ["student", "instructor", "academic_staff", "administrator"];
    if !valid_roles.contains(&req.role.as_str()) {
        return Err(Status::BadRequest);
    }

    let id = Uuid::new_v4().to_string();
    let new_pass = req.password.clone();
    let password_hash = tokio::task::spawn_blocking(move || {
        hash(&new_pass, DEFAULT_COST)
    }).await.map_err(|e| { log::error!("register: password hash spawn failed: {}", e); Status::InternalServerError })?.map_err(|e| { log::error!("register: bcrypt hash failed: {}", e); Status::InternalServerError })?;

    sqlx::query(
        "INSERT INTO users (id, username, email, password_hash, first_name, last_name, role, is_active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, true, NOW(), NOW())"
    )
    .bind(&id)
    .bind(&req.username)
    .bind(&req.email)
    .bind(&password_hash)
    .bind(&req.first_name)
    .bind(&req.last_name)
    .bind(&req.role)
    .execute(pool.inner())
    .await
    .map_err(|e| { log::error!("register: user insert failed: {}", e); Status::InternalServerError })?;

    let session_id = Uuid::new_v4().to_string();
    let token = generate_token(&id, &req.username, &req.role, &session_id)?;

    let now = Utc::now().naive_utc();
    let expires = now + Duration::minutes(models::SESSION_IDLE_TIMEOUT_MINUTES);
    sqlx::query(
        "INSERT INTO sessions (id, user_id, token, last_activity, expires_at, is_active) VALUES (?, ?, ?, ?, ?, true)"
    )
    .bind(&session_id)
    .bind(&id)
    .bind(&token)
    .bind(now)
    .bind(expires)
    .execute(pool.inner())
    .await
    .map_err(|e| { log::error!("register: session insert failed: {}", e); Status::InternalServerError })?;

    log_audit(pool.inner(), Some(&admin.user_id), "user_provisioned", Some("user"), Some(&id),
        Some(&format!("Account '{}' provisioned by admin '{}'", req.username, admin.username))).await;

    Ok(Json(LoginResponse {
        token,
        user: UserResponse {
            id, username: req.username.clone(), email: req.email.clone(),
            first_name: req.first_name.clone(), last_name: req.last_name.clone(),
            contact_info: None, role: req.role.clone(), is_active: true,
            invoice_title: None, notify_submissions: true, notify_orders: true,
            notify_reviews: true, notify_cases: true, created_at: None,
        },
    }))
}

#[get("/me")]
pub async fn me(pool: &State<DbPool>, user: AuthenticatedUser) -> Result<Json<UserResponse>, Status> {
    let row = sqlx::query_as::<_, (String, String, String, String, String, Option<String>, String, bool, Option<String>, bool, bool, bool, bool, Option<chrono::NaiveDateTime>)>(
        "SELECT id, username, email, first_name, last_name, contact_info, role, is_active, invoice_title, notify_submissions, notify_orders, notify_reviews, notify_cases, created_at FROM users WHERE id = ?"
    )
    .bind(&user.user_id)
    .fetch_optional(pool.inner())
    .await
    .map_err(|e| { log::error!("me: user query failed: {}", e); Status::InternalServerError })?;

    match row {
        Some((id, username, email, first_name, last_name, contact_info, role, is_active, invoice_title, ns, no, nr, nc, created_at)) => {
            Ok(Json(UserResponse {
                id, username, email, first_name, last_name, contact_info, role, is_active,
                invoice_title, notify_submissions: ns, notify_orders: no, notify_reviews: nr,
                notify_cases: nc, created_at,
            }))
        }
        None => Err(Status::NotFound),
    }
}

#[post("/change-password", data = "<req>")]
pub async fn change_password(pool: &State<DbPool>, user: AuthenticatedUser, req: Json<ChangePasswordRequest>) -> Result<Status, Status> {
    let row = sqlx::query_scalar::<_, String>("SELECT password_hash FROM users WHERE id = ?")
        .bind(&user.user_id)
        .fetch_optional(pool.inner())
        .await
        .map_err(|e| { log::error!("change_password: password hash query failed: {}", e); Status::InternalServerError })?;

    match row {
        Some(current_hash) => {
            let current_password = req.current_password.clone();
            let valid = tokio::task::spawn_blocking(move || {
                verify(&current_password, &current_hash).unwrap_or(false)
            }).await.unwrap_or(false);
            if !valid {
                return Err(Status::Unauthorized);
            }
            let new_password = req.new_password.clone();
            let new_hash = tokio::task::spawn_blocking(move || {
                hash(&new_password, DEFAULT_COST)
            }).await.map_err(|e| { log::error!("change_password: bcrypt hash spawn failed: {}", e); Status::InternalServerError })?.map_err(|e| { log::error!("change_password: bcrypt hash failed: {}", e); Status::InternalServerError })?;
            sqlx::query("UPDATE users SET password_hash = ?, updated_at = NOW() WHERE id = ?")
                .bind(&new_hash)
                .bind(&user.user_id)
                .execute(pool.inner())
                .await
                .map_err(|e| { log::error!("change_password: update password_hash failed: {}", e); Status::InternalServerError })?;
            log_audit(pool.inner(), Some(&user.user_id), "password_changed", Some("user"), Some(&user.user_id), None).await;
            Ok(Status::Ok)
        }
        None => Err(Status::NotFound),
    }
}

#[post("/generate-reset-token", data = "<req>")]
pub async fn generate_reset_token(pool: &State<DbPool>, user: AuthenticatedUser, req: Json<GenerateResetTokenRequest>) -> Result<Json<ResetTokenResponse>, Status> {
    user.require_permission("auth.generate_reset")?;

    // Generate random token using UUID (Send-safe)
    let token = format!("{}{}", Uuid::new_v4().to_string().replace('-', ""), &Uuid::new_v4().to_string().replace('-', "")[..16]);
    let token_id = Uuid::new_v4().to_string();
    let expires = Utc::now().naive_utc() + Duration::minutes(models::PASSWORD_RESET_EXPIRY_MINUTES);

    sqlx::query(
        "INSERT INTO password_reset_tokens (id, user_id, token, used, expires_at, created_by, created_at) VALUES (?, ?, ?, false, ?, ?, NOW())"
    )
    .bind(&token_id)
    .bind(&req.user_id)
    .bind(&token)
    .bind(&expires)
    .bind(&user.user_id)
    .execute(pool.inner())
    .await
    .map_err(|e| { log::error!("generate_reset_token: token insert failed: {}", e); Status::InternalServerError })?;

    log_audit(pool.inner(), Some(&user.user_id), "reset_token_generated", Some("user"), Some(&req.user_id), Some("Password reset token generated by admin")).await;

    Ok(Json(ResetTokenResponse {
        token,
        expires_at: expires.format("%m/%d/%Y, %I:%M:%S %p").to_string(),
    }))
}

#[post("/use-reset-token", data = "<req>")]
pub async fn use_reset_token(pool: &State<DbPool>, req: Json<UseResetTokenRequest>) -> Result<Status, Status> {
    let row = sqlx::query_as::<_, (String, String, bool, chrono::NaiveDateTime)>(
        "SELECT id, user_id, used, expires_at FROM password_reset_tokens WHERE token = ?"
    )
    .bind(&req.token)
    .fetch_optional(pool.inner())
    .await
    .map_err(|e| { log::error!("use_reset_token: token query failed: {}", e); Status::InternalServerError })?;

    match row {
        Some((token_id, user_id, used, expires_at)) => {
            if used {
                return Err(Status::Gone);
            }
            if Utc::now().naive_utc() > expires_at {
                return Err(Status::Gone);
            }

            let new_password = req.new_password.clone();
            let new_hash = tokio::task::spawn_blocking(move || {
                hash(&new_password, DEFAULT_COST)
            }).await.map_err(|e| { log::error!("use_reset_token: bcrypt hash spawn failed: {}", e); Status::InternalServerError })?.map_err(|e| { log::error!("use_reset_token: bcrypt hash failed: {}", e); Status::InternalServerError })?;

            sqlx::query("UPDATE users SET password_hash = ?, updated_at = NOW() WHERE id = ?")
                .bind(&new_hash)
                .bind(&user_id)
                .execute(pool.inner())
                .await
                .map_err(|e| { log::error!("use_reset_token: update password_hash failed: {}", e); Status::InternalServerError })?;

            sqlx::query("UPDATE password_reset_tokens SET used = true WHERE id = ?")
                .bind(&token_id)
                .execute(pool.inner())
                .await
                .map_err(|e| { log::error!("use_reset_token: update token used flag failed: {}", e); Status::InternalServerError })?;

            log_audit(pool.inner(), Some(&user_id), "password_reset_used", Some("user"), Some(&user_id), None).await;
            Ok(Status::Ok)
        }
        None => Err(Status::NotFound),
    }
}

#[post("/request-deletion")]
pub async fn request_account_deletion(pool: &State<DbPool>, user: AuthenticatedUser) -> Result<Status, Status> {
    let deletion_date = Utc::now().naive_utc() + Duration::days(models::SOFT_DELETE_HOLD_DAYS);

    sqlx::query("UPDATE users SET soft_deleted_at = NOW(), deletion_scheduled_at = ?, updated_at = NOW() WHERE id = ?")
        .bind(&deletion_date)
        .bind(&user.user_id)
        .execute(pool.inner())
        .await
        .map_err(|e| { log::error!("request_account_deletion: update soft_deleted_at failed: {}", e); Status::InternalServerError })?;

    log_audit(pool.inner(), Some(&user.user_id), "account_deletion_requested", Some("user"), Some(&user.user_id),
        Some(&format!("Scheduled for permanent deletion on {}", deletion_date.format("%m/%d/%Y")))).await;

    Ok(Status::Ok)
}

#[post("/cancel-deletion")]
pub async fn cancel_deletion(pool: &State<DbPool>, user: AuthenticatedUser) -> Result<Status, Status> {
    sqlx::query("UPDATE users SET soft_deleted_at = NULL, deletion_scheduled_at = NULL, updated_at = NOW() WHERE id = ?")
        .bind(&user.user_id)
        .execute(pool.inner())
        .await
        .map_err(|e| { log::error!("cancel_deletion: update users failed: {}", e); Status::InternalServerError })?;

    log_audit(pool.inner(), Some(&user.user_id), "account_deletion_cancelled", Some("user"), Some(&user.user_id), None).await;
    Ok(Status::Ok)
}

#[get("/export-my-data")]
pub async fn export_my_data(pool: &State<DbPool>, user: AuthenticatedUser) -> Result<(rocket::http::ContentType, Vec<u8>), Status> {
    // User profile
    let profile = sqlx::query_as::<_, (String, String, String, String, String, Option<String>, String)>(
        "SELECT id, username, email, first_name, last_name, contact_info, role FROM users WHERE id = ?"
    )
    .bind(&user.user_id)
    .fetch_optional(pool.inner())
    .await
    .map_err(|e| { log::error!("export_my_data: user profile query failed: {}", e); Status::InternalServerError })?;

    let profile_json = match profile {
        Some((id, username, email, fn_, ln, ci, role)) => serde_json::json!({
            "id": id, "username": username, "email": email,
            "first_name": fn_, "last_name": ln, "contact_info": ci, "role": role
        }),
        None => return Err(Status::NotFound),
    };

    // Addresses
    let addrs = sqlx::query_as::<_, (String, String, String, Option<String>, String, String, String, bool)>(
        "SELECT id, label, street_line1, street_line2, city, state, zip_code, is_default FROM user_addresses WHERE user_id = ?"
    )
    .bind(&user.user_id)
    .fetch_all(pool.inner())
    .await
    .map_err(|e| { log::error!("export_my_data: addresses query failed: {}", e); Status::InternalServerError })?;

    let addresses: Vec<serde_json::Value> = addrs.into_iter().map(|(id, label, s1, s2, city, state, zip, def)| {
        serde_json::json!({"id": id, "label": label, "street_line1": s1, "street_line2": s2, "city": city, "state": state, "zip_code": zip, "is_default": def})
    }).collect();

    // Submissions
    let subs = sqlx::query_as::<_, (String, String, String, String)>(
        "SELECT id, title, submission_type, status FROM submissions WHERE author_id = ?"
    )
    .bind(&user.user_id)
    .fetch_all(pool.inner())
    .await
    .map_err(|e| { log::error!("export_my_data: submissions query failed: {}", e); Status::InternalServerError })?;

    let submissions: Vec<serde_json::Value> = subs.into_iter().map(|(id, title, st, status)| {
        serde_json::json!({"id": id, "title": title, "submission_type": st, "status": status})
    }).collect();

    // Orders
    let ords = sqlx::query_as::<_, (String, String, String, String, String)>(
        "SELECT id, order_number, subscription_period, status, CAST(total_amount AS CHAR) FROM orders WHERE user_id = ?"
    )
    .bind(&user.user_id)
    .fetch_all(pool.inner())
    .await
    .map_err(|e| { log::error!("export_my_data: orders query failed: {}", e); Status::InternalServerError })?;

    let orders: Vec<serde_json::Value> = ords.into_iter().map(|(id, num, period, status, total)| {
        serde_json::json!({"id": id, "order_number": num, "subscription_period": period, "status": status, "total_amount": total})
    }).collect();

    // Reviews
    let revs = sqlx::query_as::<_, (String, String, i32, String)>(
        "SELECT id, title, rating, body FROM reviews WHERE user_id = ?"
    )
    .bind(&user.user_id)
    .fetch_all(pool.inner())
    .await
    .map_err(|e| { log::error!("export_my_data: reviews query failed: {}", e); Status::InternalServerError })?;

    let reviews: Vec<serde_json::Value> = revs.into_iter().map(|(id, title, rating, body)| {
        serde_json::json!({"id": id, "title": title, "rating": rating, "body": body})
    }).collect();

    // Cases
    let cases = sqlx::query_as::<_, (String, String, String, String)>(
        "SELECT id, case_type, subject, status FROM after_sales_cases WHERE reporter_id = ?"
    )
    .bind(&user.user_id)
    .fetch_all(pool.inner())
    .await
    .map_err(|e| { log::error!("export_my_data: cases query failed: {}", e); Status::InternalServerError })?;

    let cases_json: Vec<serde_json::Value> = cases.into_iter().map(|(id, ct, subj, status)| {
        serde_json::json!({"id": id, "case_type": ct, "subject": subj, "status": status})
    }).collect();

    log_audit(pool.inner(), Some(&user.user_id), "data_exported", Some("user"), Some(&user.user_id), None).await;

    let export = ExportDataResponse {
        user_profile: profile_json,
        addresses,
        submissions,
        orders,
        reviews,
        cases: cases_json,
        exported_at: Utc::now().naive_utc().format("%m/%d/%Y, %I:%M:%S %p").to_string(),
    };

    // Return as downloadable JSON archive
    let json_bytes = serde_json::to_vec_pretty(&export).map_err(|e| { log::error!("export_my_data: JSON serialization failed: {}", e); Status::InternalServerError })?;
    Ok((rocket::http::ContentType::JSON, json_bytes))
}

#[post("/logout")]
pub async fn logout(pool: &State<DbPool>, user: AuthenticatedUser) -> Result<Status, Status> {
    sqlx::query("UPDATE sessions SET is_active = false WHERE user_id = ? AND is_active = true")
        .bind(&user.user_id)
        .execute(pool.inner())
        .await
        .map_err(|e| { log::error!("logout: deactivate sessions failed: {}", e); Status::InternalServerError })?;

    Ok(Status::Ok)
}
