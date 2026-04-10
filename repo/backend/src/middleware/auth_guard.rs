use crate::models::auth::Claims;
use jsonwebtoken::{decode, DecodingKey, Validation};
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};

#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub user_id: String,
    pub username: String,
    pub role: String,
    pub session_id: String,
    pub permissions: Vec<String>,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthenticatedUser {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let jwt_secret = match std::env::var("JWT_SECRET") {
            Ok(s) if s.len() >= 32 => s,
            _ => {
                log::error!("JWT_SECRET not set or too short — refusing auth");
                return Outcome::Error((Status::ServiceUnavailable, "Server misconfigured"));
            }
        };

        let auth_header = request.headers().get_one("Authorization");

        match auth_header {
            Some(header) if header.starts_with("Bearer ") => {
                let token = &header[7..];
                match decode::<Claims>(
                    token,
                    &DecodingKey::from_secret(jwt_secret.as_bytes()),
                    &Validation::default(),
                ) {
                    Ok(token_data) => {
                        let claims = token_data.claims;

                        // --- FAIL-CLOSED: DB pool must be available ---
                        let pool = match request.rocket().state::<crate::DbPool>() {
                            Some(p) => p,
                            None => {
                                log::error!("DB pool unavailable — denying request (fail-closed)");
                                return Outcome::Error((
                                    Status::ServiceUnavailable,
                                    "Service unavailable",
                                ));
                            }
                        };

                        // --- FAIL-CLOSED: session check must succeed ---
                        let session_check = sqlx::query_as::<_, (bool, chrono::NaiveDateTime)>(
                            "SELECT is_active, expires_at FROM sessions WHERE id = ? AND user_id = ?",
                        )
                        .bind(&claims.session_id)
                        .bind(&claims.sub)
                        .fetch_optional(pool)
                        .await;

                        match session_check {
                            Ok(Some((is_active, expires_at))) => {
                                let now = chrono::Utc::now().naive_utc();
                                if !is_active || now > expires_at {
                                    return Outcome::Error((
                                        Status::Unauthorized,
                                        "Session expired",
                                    ));
                                }
                                // Refresh idle timeout
                                let new_expiry = now
                                    + chrono::Duration::minutes(
                                        crate::models::SESSION_IDLE_TIMEOUT_MINUTES,
                                    );
                                let _ = sqlx::query(
                                    "UPDATE sessions SET last_activity = ?, expires_at = ? WHERE id = ?",
                                )
                                .bind(now)
                                .bind(new_expiry)
                                .bind(&claims.session_id)
                                .execute(pool)
                                .await;
                            }
                            Ok(None) => {
                                return Outcome::Error((
                                    Status::Unauthorized,
                                    "Session not found",
                                ));
                            }
                            Err(e) => {
                                // FAIL-CLOSED: DB error → deny
                                log::error!(
                                    "Session DB check failed for user {}: {} — denying (fail-closed)",
                                    claims.sub, e
                                );
                                return Outcome::Error((
                                    Status::ServiceUnavailable,
                                    "Session verification unavailable",
                                ));
                            }
                        }

                        // --- FAIL-CLOSED: Re-check user state from DB (fresh role, active, not soft-deleted) ---
                        let user_state = sqlx::query_as::<_, (String, bool, Option<chrono::NaiveDateTime>)>(
                            "SELECT role, is_active, soft_deleted_at FROM users WHERE id = ?",
                        )
                        .bind(&claims.sub)
                        .fetch_optional(pool)
                        .await;

                        let db_role = match user_state {
                            Ok(Some((role, is_active, soft_deleted_at))) => {
                                if !is_active {
                                    log::warn!("Auth denied: user {} is deactivated", claims.sub);
                                    return Outcome::Error((
                                        Status::Forbidden,
                                        "Account deactivated",
                                    ));
                                }
                                // Allow soft-deleted users to access cancel-deletion endpoint
                                if soft_deleted_at.is_some() {
                                    let uri = request.uri().path().as_str();
                                    if uri != "/api/auth/cancel-deletion" {
                                        log::warn!("Auth denied: user {} is soft-deleted", claims.sub);
                                        return Outcome::Error((
                                            Status::Forbidden,
                                            "Account scheduled for deletion",
                                        ));
                                    }
                                }
                                role
                            }
                            Ok(None) => {
                                return Outcome::Error((
                                    Status::Unauthorized,
                                    "User not found",
                                ));
                            }
                            Err(e) => {
                                log::error!(
                                    "User state DB check failed for {}: {} — denying (fail-closed)",
                                    claims.sub, e
                                );
                                return Outcome::Error((
                                    Status::ServiceUnavailable,
                                    "User verification unavailable",
                                ));
                            }
                        };

                        // --- Load permissions from role_permissions using FRESH DB role ---
                        let permissions: Vec<String> = sqlx::query_scalar::<_, String>(
                            "SELECT p.name FROM permissions p \
                             INNER JOIN role_permissions rp ON rp.permission_id = p.id \
                             INNER JOIN roles r ON r.id = rp.role_id \
                             WHERE r.name = ?",
                        )
                        .bind(&db_role)
                        .fetch_all(pool)
                        .await
                        .unwrap_or_default();

                        Outcome::Success(AuthenticatedUser {
                            user_id: claims.sub,
                            username: claims.username,
                            role: db_role,
                            session_id: claims.session_id,
                            permissions,
                        })
                    }
                    Err(_) => Outcome::Error((Status::Unauthorized, "Invalid token")),
                }
            }
            _ => Outcome::Error((Status::Unauthorized, "Missing authorization header")),
        }
    }
}

impl AuthenticatedUser {
    /// Check if user has a specific permission
    pub fn has_permission(&self, perm: &str) -> bool {
        self.permissions.iter().any(|p| p == perm)
    }

    /// Require a permission or return 403
    pub fn require_permission(&self, perm: &str) -> Result<(), rocket::http::Status> {
        if self.has_permission(perm) {
            Ok(())
        } else {
            Err(rocket::http::Status::Forbidden)
        }
    }

    /// Require any of the given permissions, or return 403.
    pub fn require_any_permission(&self, perms: &[&str]) -> Result<(), rocket::http::Status> {
        if perms.iter().any(|p| self.has_permission(p)) {
            Ok(())
        } else {
            Err(rocket::http::Status::Forbidden)
        }
    }

    /// True if this user has staff-level or admin-level permissions.
    pub fn is_privileged(&self) -> bool {
        self.has_permission("users.list") || self.has_permission("admin.dashboard")
    }

    /// Require privileged access (staff or admin) or return 403.
    pub fn require_privileged(&self) -> Result<(), rocket::http::Status> {
        if self.is_privileged() {
            Ok(())
        } else {
            Err(rocket::http::Status::Forbidden)
        }
    }

    /// Require that the user is either the owner of the resource or privileged.
    pub fn require_owner_or_privileged(&self, resource_owner_id: &str) -> Result<(), rocket::http::Status> {
        if self.user_id == resource_owner_id || self.is_privileged() {
            Ok(())
        } else {
            Err(rocket::http::Status::Forbidden)
        }
    }
}
