use crate::middleware::AuthenticatedUser;
use crate::models::user::*;
use crate::DbPool;
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::State;
use uuid::Uuid;

#[get("/")]
pub async fn list_users(pool: &State<DbPool>, user: AuthenticatedUser) -> Result<Json<Vec<UserResponse>>, Status> {
    user.require_privileged()?;

    let rows = sqlx::query_as::<_, (String, String, String, String, String, Option<String>, String, bool, Option<String>, bool, bool, bool, bool, Option<chrono::NaiveDateTime>)>(
        "SELECT id, username, email, first_name, last_name, contact_info, role, is_active, invoice_title, notify_submissions, notify_orders, notify_reviews, notify_cases, created_at FROM users WHERE soft_deleted_at IS NULL ORDER BY created_at DESC"
    )
    .fetch_all(pool.inner())
    .await
    .map_err(|e| { log::error!("list_users: select users query failed: {}", e); Status::InternalServerError })?;

    let users: Vec<UserResponse> = rows.into_iter().map(|(id, username, email, first_name, last_name, contact_info, role, is_active, invoice_title, ns, no, nr, nc, created_at)| {
        UserResponse { id, username, email, first_name, last_name, contact_info, role, is_active, invoice_title, notify_submissions: ns, notify_orders: no, notify_reviews: nr, notify_cases: nc, created_at }
    }).collect();

    Ok(Json(users))
}

#[get("/<user_id>")]
pub async fn get_user(pool: &State<DbPool>, auth: AuthenticatedUser, user_id: String) -> Result<Json<UserResponse>, Status> {
    if auth.user_id != user_id && !auth.is_privileged() {
        return Err(Status::Forbidden);
    }

    let row = sqlx::query_as::<_, (String, String, String, String, String, Option<String>, String, bool, Option<String>, bool, bool, bool, bool, Option<chrono::NaiveDateTime>)>(
        "SELECT id, username, email, first_name, last_name, contact_info, role, is_active, invoice_title, notify_submissions, notify_orders, notify_reviews, notify_cases, created_at FROM users WHERE id = ?"
    )
    .bind(&user_id)
    .fetch_optional(pool.inner())
    .await
    .map_err(|e| { log::error!("get_user: select user query failed: {}", e); Status::InternalServerError })?;

    match row {
        Some((id, username, email, first_name, last_name, contact_info, role, is_active, invoice_title, ns, no, nr, nc, created_at)) => {
            Ok(Json(UserResponse { id, username, email, first_name, last_name, contact_info, role, is_active, invoice_title, notify_submissions: ns, notify_orders: no, notify_reviews: nr, notify_cases: nc, created_at }))
        }
        None => Err(Status::NotFound),
    }
}

#[put("/profile", data = "<req>")]
pub async fn update_profile(pool: &State<DbPool>, auth: AuthenticatedUser, req: Json<UpdateProfileRequest>) -> Result<Status, Status> {
    if let Some(ref first_name) = req.first_name {
        sqlx::query("UPDATE users SET first_name = ?, updated_at = NOW() WHERE id = ?")
            .bind(first_name).bind(&auth.user_id).execute(pool.inner()).await.map_err(|e| { log::error!("update_profile: update first_name failed: {}", e); Status::InternalServerError })?;
    }
    if let Some(ref last_name) = req.last_name {
        sqlx::query("UPDATE users SET last_name = ?, updated_at = NOW() WHERE id = ?")
            .bind(last_name).bind(&auth.user_id).execute(pool.inner()).await.map_err(|e| { log::error!("update_profile: update last_name failed: {}", e); Status::InternalServerError })?;
    }
    if let Some(ref username) = req.username {
        let exists = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE username = ? AND id != ?")
            .bind(username).bind(&auth.user_id).fetch_one(pool.inner()).await.map_err(|e| { log::error!("update_profile: username duplicate check failed: {}", e); Status::InternalServerError })?;
        if exists > 0 { return Err(Status::Conflict); }
        sqlx::query("UPDATE users SET username = ?, updated_at = NOW() WHERE id = ?")
            .bind(username).bind(&auth.user_id).execute(pool.inner()).await.map_err(|e| { log::error!("update_profile: update username failed: {}", e); Status::InternalServerError })?;
    }
    if let Some(ref contact_info) = req.contact_info {
        sqlx::query("UPDATE users SET contact_info = ?, updated_at = NOW() WHERE id = ?")
            .bind(contact_info).bind(&auth.user_id).execute(pool.inner()).await.map_err(|e| { log::error!("update_profile: update contact_info failed: {}", e); Status::InternalServerError })?;
    }
    if let Some(ref invoice_title) = req.invoice_title {
        sqlx::query("UPDATE users SET invoice_title = ?, updated_at = NOW() WHERE id = ?")
            .bind(invoice_title).bind(&auth.user_id).execute(pool.inner()).await.map_err(|e| { log::error!("update_profile: update invoice_title failed: {}", e); Status::InternalServerError })?;
    }
    Ok(Status::Ok)
}

#[put("/notification-prefs", data = "<req>")]
pub async fn update_notification_prefs(pool: &State<DbPool>, auth: AuthenticatedUser, req: Json<UpdateNotificationPrefsRequest>) -> Result<Status, Status> {
    if let Some(v) = req.notify_submissions {
        sqlx::query("UPDATE users SET notify_submissions = ?, updated_at = NOW() WHERE id = ?")
            .bind(v).bind(&auth.user_id).execute(pool.inner()).await.map_err(|e| { log::error!("update_notification_prefs: update notify_submissions failed: {}", e); Status::InternalServerError })?;
    }
    if let Some(v) = req.notify_orders {
        sqlx::query("UPDATE users SET notify_orders = ?, updated_at = NOW() WHERE id = ?")
            .bind(v).bind(&auth.user_id).execute(pool.inner()).await.map_err(|e| { log::error!("update_notification_prefs: update notify_orders failed: {}", e); Status::InternalServerError })?;
    }
    if let Some(v) = req.notify_reviews {
        sqlx::query("UPDATE users SET notify_reviews = ?, updated_at = NOW() WHERE id = ?")
            .bind(v).bind(&auth.user_id).execute(pool.inner()).await.map_err(|e| { log::error!("update_notification_prefs: update notify_reviews failed: {}", e); Status::InternalServerError })?;
    }
    if let Some(v) = req.notify_cases {
        sqlx::query("UPDATE users SET notify_cases = ?, updated_at = NOW() WHERE id = ?")
            .bind(v).bind(&auth.user_id).execute(pool.inner()).await.map_err(|e| { log::error!("update_notification_prefs: update notify_cases failed: {}", e); Status::InternalServerError })?;
    }
    Ok(Status::Ok)
}

#[put("/<user_id>/role", data = "<req>")]
pub async fn update_user_role(pool: &State<DbPool>, auth: AuthenticatedUser, user_id: String, req: Json<UpdateUserRoleRequest>) -> Result<Status, Status> {
    auth.require_permission("users.role_change")?;
    let valid_roles = ["student", "instructor", "academic_staff", "administrator"];
    if !valid_roles.contains(&req.role.as_str()) {
        return Err(Status::BadRequest);
    }

    // Get old role for audit
    let old_role = sqlx::query_scalar::<_, String>("SELECT role FROM users WHERE id = ?")
        .bind(&user_id).fetch_optional(pool.inner()).await.map_err(|e| { log::error!("update_user_role: select role query failed: {}", e); Status::InternalServerError })?;

    sqlx::query("UPDATE users SET role = ?, updated_at = NOW() WHERE id = ?")
        .bind(&req.role).bind(&user_id).execute(pool.inner()).await.map_err(|e| { log::error!("update_user_role: update role failed: {}", e); Status::InternalServerError })?;

    // Invalidate all active sessions for this user so stale JWT claims are not used
    sqlx::query("UPDATE sessions SET is_active = false WHERE user_id = ? AND is_active = true")
        .bind(&user_id).execute(pool.inner()).await.map_err(|e| { log::error!("update_user_role: session invalidation failed: {}", e); Status::InternalServerError })?;

    // Audit log for permission change
    let details = format!("Role changed from '{}' to '{}'", old_role.unwrap_or_default(), req.role);
    let _ = sqlx::query("INSERT INTO audit_log (id, user_id, action, target_type, target_id, details, created_at) VALUES (?, ?, 'role_changed', 'user', ?, ?, NOW())")
        .bind(Uuid::new_v4().to_string()).bind(&auth.user_id).bind(&user_id).bind(&details)
        .execute(pool.inner()).await;

    Ok(Status::Ok)
}

#[delete("/<user_id>")]
pub async fn deactivate_user(pool: &State<DbPool>, auth: AuthenticatedUser, user_id: String) -> Result<Status, Status> {
    // Only administrators can deactivate user accounts
    if auth.role != "administrator" {
        return Err(Status::Forbidden);
    }
    auth.require_permission("users.manage")?;
    sqlx::query("UPDATE users SET is_active = false, updated_at = NOW() WHERE id = ?")
        .bind(&user_id).execute(pool.inner()).await.map_err(|e| { log::error!("deactivate_user: update is_active failed: {}", e); Status::InternalServerError })?;

    // Invalidate all active sessions for the deactivated user
    sqlx::query("UPDATE sessions SET is_active = false WHERE user_id = ? AND is_active = true")
        .bind(&user_id).execute(pool.inner()).await.map_err(|e| { log::error!("deactivate_user: session invalidation failed: {}", e); Status::InternalServerError })?;

    let _ = sqlx::query("INSERT INTO audit_log (id, user_id, action, target_type, target_id, details, created_at) VALUES (?, ?, 'user_deactivated', 'user', ?, 'User deactivated by admin', NOW())")
        .bind(Uuid::new_v4().to_string()).bind(&auth.user_id).bind(&user_id)
        .execute(pool.inner()).await;

    Ok(Status::NoContent)
}

// --- Addresses ---

#[get("/addresses")]
pub async fn list_addresses(pool: &State<DbPool>, auth: AuthenticatedUser) -> Result<Json<Vec<UserAddress>>, Status> {
    let rows = sqlx::query_as::<_, (String, String, String, String, Option<String>, String, String, String, bool)>(
        "SELECT id, user_id, label, street_line1, street_line2, city, state, zip_code, is_default FROM user_addresses WHERE user_id = ? ORDER BY is_default DESC"
    )
    .bind(&auth.user_id)
    .fetch_all(pool.inner())
    .await
    .map_err(|e| { log::error!("list_addresses: select addresses query failed: {}", e); Status::InternalServerError })?;

    let addrs: Vec<UserAddress> = rows.into_iter().map(|(id, user_id, label, s1, s2, city, state, zip, def)| {
        UserAddress { id, user_id, label, street_line1: s1, street_line2: s2, city, state, zip_code: zip, is_default: def }
    }).collect();

    Ok(Json(addrs))
}

#[post("/addresses", data = "<req>")]
pub async fn create_address(pool: &State<DbPool>, auth: AuthenticatedUser, req: Json<CreateAddressRequest>) -> Result<Json<UserAddress>, Status> {
    if req.state.len() != 2 {
        return Err(Status::BadRequest);
    }

    let id = Uuid::new_v4().to_string();
    let is_default = req.is_default.unwrap_or(false);

    // If setting as default, unset others
    if is_default {
        sqlx::query("UPDATE user_addresses SET is_default = false WHERE user_id = ?")
            .bind(&auth.user_id).execute(pool.inner()).await.map_err(|e| { log::error!("create_address: unset default addresses failed: {}", e); Status::InternalServerError })?;
    }

    sqlx::query(
        "INSERT INTO user_addresses (id, user_id, label, street_line1, street_line2, city, state, zip_code, is_default) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&id).bind(&auth.user_id).bind(&req.label).bind(&req.street_line1).bind(&req.street_line2)
    .bind(&req.city).bind(&req.state).bind(&req.zip_code).bind(is_default)
    .execute(pool.inner()).await.map_err(|e| { log::error!("create_address: insert address failed: {}", e); Status::InternalServerError })?;

    Ok(Json(UserAddress {
        id, user_id: auth.user_id, label: req.label.clone(), street_line1: req.street_line1.clone(),
        street_line2: req.street_line2.clone(), city: req.city.clone(), state: req.state.clone(),
        zip_code: req.zip_code.clone(), is_default,
    }))
}

#[put("/addresses/default", data = "<req>")]
pub async fn set_default_address(pool: &State<DbPool>, auth: AuthenticatedUser, req: Json<SetDefaultAddressRequest>) -> Result<Status, Status> {
    // Verify the address exists and belongs to this user before clearing defaults
    let exists = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM user_addresses WHERE id = ? AND user_id = ?"
    )
    .bind(&req.address_id).bind(&auth.user_id)
    .fetch_one(pool.inner()).await
    .map_err(|e| { log::error!("set_default_address: existence check failed: {}", e); Status::InternalServerError })?;

    if exists == 0 {
        return Err(Status::NotFound);
    }

    // Unset all defaults for this user
    sqlx::query("UPDATE user_addresses SET is_default = false WHERE user_id = ?")
        .bind(&auth.user_id).execute(pool.inner()).await.map_err(|e| { log::error!("set_default_address: unset defaults failed: {}", e); Status::InternalServerError })?;

    // Set the new default
    let result = sqlx::query("UPDATE user_addresses SET is_default = true WHERE id = ? AND user_id = ?")
        .bind(&req.address_id).bind(&auth.user_id).execute(pool.inner()).await.map_err(|e| { log::error!("set_default_address: update default failed: {}", e); Status::InternalServerError })?;

    if result.rows_affected() == 0 {
        log::error!("set_default_address: failed to set default for address {} — rolling back", req.address_id);
        return Err(Status::InternalServerError);
    }

    Ok(Status::Ok)
}

#[delete("/addresses/<address_id>")]
pub async fn delete_address(pool: &State<DbPool>, auth: AuthenticatedUser, address_id: String) -> Result<Status, Status> {
    // Check if we're deleting the default address
    let was_default = sqlx::query_scalar::<_, bool>(
        "SELECT is_default FROM user_addresses WHERE id = ? AND user_id = ?"
    )
    .bind(&address_id).bind(&auth.user_id)
    .fetch_optional(pool.inner()).await
    .map_err(|e| { log::error!("delete_address: default check failed: {}", e); Status::InternalServerError })?;

    let result = sqlx::query("DELETE FROM user_addresses WHERE id = ? AND user_id = ?")
        .bind(&address_id).bind(&auth.user_id).execute(pool.inner()).await.map_err(|e| { log::error!("delete_address: delete address failed: {}", e); Status::InternalServerError })?;

    if result.rows_affected() == 0 {
        return Err(Status::NotFound);
    }

    // If we deleted the default, promote the most recently created remaining address
    if was_default == Some(true) {
        let _ = sqlx::query(
            "UPDATE user_addresses SET is_default = true WHERE user_id = ? ORDER BY id DESC LIMIT 1"
        )
        .bind(&auth.user_id).execute(pool.inner()).await;
    }

    Ok(Status::NoContent)
}

// --- Notifications ---

#[get("/notifications")]
pub async fn get_notifications(pool: &State<DbPool>, auth: AuthenticatedUser) -> Result<Json<Vec<NotificationItem>>, Status> {
    let rows = sqlx::query_as::<_, (String, String, String, bool, Option<chrono::NaiveDateTime>)>(
        "SELECT id, title, message, is_read, created_at FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 50"
    )
    .bind(&auth.user_id)
    .fetch_all(pool.inner())
    .await
    .map_err(|e| { log::error!("get_notifications: select notifications query failed: {}", e); Status::InternalServerError })?;

    let notifs: Vec<NotificationItem> = rows.into_iter().map(|(id, title, message, is_read, created_at)| {
        NotificationItem { id, title, message, is_read, created_at }
    }).collect();

    Ok(Json(notifs))
}

#[put("/notifications/<notif_id>/read")]
pub async fn mark_notification_read(pool: &State<DbPool>, auth: AuthenticatedUser, notif_id: String) -> Result<Status, Status> {
    sqlx::query("UPDATE notifications SET is_read = true WHERE id = ? AND user_id = ?")
        .bind(&notif_id).bind(&auth.user_id).execute(pool.inner()).await.map_err(|e| { log::error!("mark_notification_read: update notification failed: {}", e); Status::InternalServerError })?;
    Ok(Status::Ok)
}
