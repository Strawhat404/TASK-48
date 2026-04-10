use crate::middleware::AuthenticatedUser;
use crate::models::payment::*;
use crate::DbPool;
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::State;
use uuid::Uuid;
use rust_decimal::Decimal;

#[post("/", data = "<req>")]
pub async fn create_payment(pool: &State<DbPool>, user: AuthenticatedUser, req: Json<CreatePaymentRequest>) -> Result<Json<Payment>, Status> {
    user.require_permission("payments.manage")?;

    let valid_methods = ["cash", "check", "on_account"];
    if !valid_methods.contains(&req.payment_method.as_str()) {
        return Err(Status::BadRequest);
    }

    let valid_types = ["charge", "hold", "release", "refund"];
    if !valid_types.contains(&req.transaction_type.as_str()) {
        return Err(Status::BadRequest);
    }

    // Idempotency check — if this key already exists, return the existing payment
    let existing = sqlx::query_as::<_, (String, String, String, String, rust_decimal::Decimal, String, Option<String>, String, Option<String>, Option<String>, Option<String>, Option<chrono::NaiveDateTime>, Option<chrono::NaiveDateTime>)>(
        "SELECT id, order_id, idempotency_key, payment_method, amount, transaction_type, reference_payment_id, status, check_number, notes, processed_by, created_at, updated_at FROM payments WHERE idempotency_key = ?"
    )
    .bind(&req.idempotency_key)
    .fetch_optional(pool.inner())
    .await
    .map_err(|e| { log::error!("create_payment: idempotency check query failed: {}", e); Status::InternalServerError })?;

    if let Some((id, oid, ik, pm, amount, tt, rpi, status, cn, notes, pb, ca, ua)) = existing {
        return Ok(Json(Payment {
            id, order_id: oid, idempotency_key: ik, payment_method: pm, amount: amount.to_string().parse().unwrap_or(0.0),
            transaction_type: tt, reference_payment_id: rpi, status, check_number: cn,
            notes, processed_by: pb, created_at: ca, updated_at: ua,
        }));
    }

    let id = Uuid::new_v4().to_string();
    let status = match req.transaction_type.as_str() {
        "hold" => "held",
        "charge" => "completed",
        "release" => "released",
        "refund" => "refunded",
        _ => "pending",
    };

    sqlx::query(
        "INSERT INTO payments (id, order_id, idempotency_key, payment_method, amount, transaction_type, reference_payment_id, status, check_number, notes, processed_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())"
    )
    .bind(&id).bind(&req.order_id).bind(&req.idempotency_key).bind(&req.payment_method)
    .bind(req.amount).bind(&req.transaction_type).bind(&req.reference_payment_id)
    .bind(status).bind(&req.check_number).bind(&req.notes).bind(&user.user_id)
    .execute(pool.inner()).await.map_err(|e| { log::error!("create_payment: insert payment failed: {}", e); Status::InternalServerError })?;

    // Update order payment status
    match req.transaction_type.as_str() {
        "charge" => {
            sqlx::query("UPDATE orders SET payment_status = 'paid', updated_at = NOW() WHERE id = ?")
                .bind(&req.order_id).execute(pool.inner()).await.map_err(|e| { log::error!("create_payment: update order payment_status to paid failed: {}", e); Status::InternalServerError })?;
        }
        "hold" => {
            sqlx::query("UPDATE orders SET payment_status = 'held', updated_at = NOW() WHERE id = ?")
                .bind(&req.order_id).execute(pool.inner()).await.map_err(|e| { log::error!("create_payment: update order payment_status to held failed: {}", e); Status::InternalServerError })?;
        }
        "refund" => {
            sqlx::query("UPDATE orders SET payment_status = 'refunded', updated_at = NOW() WHERE id = ?")
                .bind(&req.order_id).execute(pool.inner()).await.map_err(|e| { log::error!("create_payment: update order payment_status to refunded failed: {}", e); Status::InternalServerError })?;
        }
        _ => {}
    }

    Ok(Json(Payment {
        id, order_id: req.order_id.clone(), idempotency_key: req.idempotency_key.clone(),
        payment_method: req.payment_method.clone(), amount: req.amount,
        transaction_type: req.transaction_type.clone(), reference_payment_id: req.reference_payment_id.clone(),
        status: status.to_string(), check_number: req.check_number.clone(),
        notes: req.notes.clone(), processed_by: Some(user.user_id),
        created_at: None, updated_at: None,
    }))
}

#[post("/refund", data = "<req>")]
pub async fn refund_payment(pool: &State<DbPool>, user: AuthenticatedUser, req: Json<RefundPaymentRequest>) -> Result<Json<Payment>, Status> {
    user.require_permission("payments.manage")?;

    // Idempotency check
    let existing = sqlx::query_scalar::<_, String>("SELECT id FROM payments WHERE idempotency_key = ?")
        .bind(&req.idempotency_key).fetch_optional(pool.inner()).await.map_err(|e| { log::error!("refund_payment: idempotency check query failed: {}", e); Status::InternalServerError })?;

    if let Some(existing_id) = existing {
        // Idempotent: return the existing refund payment (HTTP 200, not a double-charge)
        let existing_row = sqlx::query_as::<_, (String, String, String, String, rust_decimal::Decimal, String, Option<String>, String, Option<String>, Option<String>, Option<String>, Option<chrono::NaiveDateTime>, Option<chrono::NaiveDateTime>)>(
            "SELECT id, order_id, idempotency_key, payment_method, amount, transaction_type, reference_payment_id, status, check_number, notes, processed_by, created_at, updated_at FROM payments WHERE id = ?"
        ).bind(&existing_id).fetch_one(pool.inner()).await.map_err(|e| { log::error!("refund_payment: select existing refund failed: {}", e); Status::InternalServerError })?;
        let (id, oid, ik, pm, amount, tt, rpi, status, cn, notes, pb, ca, ua) = existing_row;
        return Ok(Json(Payment {
            id, order_id: oid, idempotency_key: ik, payment_method: pm, amount: amount.to_string().parse().unwrap_or(0.0),
            transaction_type: tt, reference_payment_id: rpi, status, check_number: cn,
            notes, processed_by: pb, created_at: ca, updated_at: ua,
        }));
    }

    // Get original payment
    let orig = sqlx::query_as::<_, (String, String, rust_decimal::Decimal, String)>(
        "SELECT id, order_id, amount, status FROM payments WHERE id = ?"
    )
    .bind(&req.original_payment_id).fetch_optional(pool.inner()).await.map_err(|e| { log::error!("refund_payment: select original payment failed: {}", e); Status::InternalServerError })?;

    match orig {
        Some((orig_id, order_id, orig_amount, orig_status)) => {
            if orig_status != "completed" && orig_status != "held" {
                return Err(Status::BadRequest);
            }
            let orig_amount_f64: f64 = orig_amount.to_string().parse().unwrap_or(0.0);
            if req.amount > orig_amount_f64 {
                return Err(Status::BadRequest);
            }

            let id = Uuid::new_v4().to_string();

            sqlx::query(
                "INSERT INTO payments (id, order_id, idempotency_key, payment_method, amount, transaction_type, reference_payment_id, status, notes, processed_by, created_at, updated_at) VALUES (?, ?, ?, 'on_account', ?, 'refund', ?, 'refunded', ?, ?, NOW(), NOW())"
            )
            .bind(&id).bind(&order_id).bind(&req.idempotency_key).bind(req.amount)
            .bind(&orig_id).bind(&req.reason).bind(&user.user_id)
            .execute(pool.inner()).await.map_err(|e| { log::error!("refund_payment: insert refund payment failed: {}", e); Status::InternalServerError })?;

            // Update order payment status
            if (req.amount - orig_amount_f64).abs() < 0.01 {
                sqlx::query("UPDATE orders SET payment_status = 'refunded', updated_at = NOW() WHERE id = ?")
                    .bind(&order_id).execute(pool.inner()).await.map_err(|e| { log::error!("refund_payment: update order status to refunded failed: {}", e); Status::InternalServerError })?;
            } else {
                sqlx::query("UPDATE orders SET payment_status = 'partial_refund', updated_at = NOW() WHERE id = ?")
                    .bind(&order_id).execute(pool.inner()).await.map_err(|e| { log::error!("refund_payment: update order status to partial_refund failed: {}", e); Status::InternalServerError })?;
            }

            Ok(Json(Payment {
                id, order_id, idempotency_key: req.idempotency_key.clone(),
                payment_method: "on_account".to_string(), amount: req.amount,
                transaction_type: "refund".to_string(), reference_payment_id: Some(orig_id),
                status: "refunded".to_string(), check_number: None,
                notes: req.reason.clone(), processed_by: Some(user.user_id),
                created_at: None, updated_at: None,
            }))
        }
        None => Err(Status::NotFound),
    }
}

#[get("/order/<order_id>")]
pub async fn list_payments(pool: &State<DbPool>, user: AuthenticatedUser, order_id: String) -> Result<Json<Vec<Payment>>, Status> {
    if !user.is_privileged() {
        // Users can see payments for their own orders
        let owner = sqlx::query_scalar::<_, String>("SELECT user_id FROM orders WHERE id = ?")
            .bind(&order_id).fetch_optional(pool.inner()).await.map_err(|e| { log::error!("list_payments: select order owner failed: {}", e); Status::InternalServerError })?;
        match owner {
            Some(uid) if uid != user.user_id => return Err(Status::Forbidden),
            None => return Err(Status::NotFound),
            _ => {}
        }
    }

    let rows = sqlx::query_as::<_, (String, String, String, String, rust_decimal::Decimal, String, Option<String>, String, Option<String>, Option<String>, Option<String>, Option<chrono::NaiveDateTime>, Option<chrono::NaiveDateTime>)>(
        "SELECT id, order_id, idempotency_key, payment_method, amount, transaction_type, reference_payment_id, status, check_number, notes, processed_by, created_at, updated_at FROM payments WHERE order_id = ? ORDER BY created_at DESC"
    )
    .bind(&order_id).fetch_all(pool.inner()).await.map_err(|e| { log::error!("list_payments: select payments query failed: {}", e); Status::InternalServerError })?;

    let payments: Vec<Payment> = rows.into_iter().map(|(id, oid, ik, pm, amount, tt, rpi, status, cn, notes, pb, ca, ua)| {
        Payment { id, order_id: oid, idempotency_key: ik, payment_method: pm, amount: amount.to_string().parse().unwrap_or(0.0), transaction_type: tt, reference_payment_id: rpi, status, check_number: cn, notes, processed_by: pb, created_at: ca, updated_at: ua }
    }).collect();

    Ok(Json(payments))
}

#[get("/reconciliation-report")]
pub async fn get_reconciliation_report(pool: &State<DbPool>, user: AuthenticatedUser) -> Result<Json<serde_json::Value>, Status> {
    user.require_permission("admin.dashboard")?;

    let total_charges = sqlx::query_scalar::<_, f64>(
        "SELECT COALESCE(SUM(amount), 0) FROM payments WHERE transaction_type = 'charge' AND status = 'completed'"
    )
    .fetch_one(pool.inner()).await.unwrap_or(0.0);

    let total_holds = sqlx::query_scalar::<_, f64>(
        "SELECT COALESCE(SUM(amount), 0) FROM payments WHERE transaction_type = 'hold' AND status = 'held'"
    )
    .fetch_one(pool.inner()).await.unwrap_or(0.0);

    let total_refunds = sqlx::query_scalar::<_, f64>(
        "SELECT COALESCE(SUM(amount), 0) FROM payments WHERE transaction_type = 'refund'"
    )
    .fetch_one(pool.inner()).await.unwrap_or(0.0);

    let expected_balance = total_charges - total_refunds;
    let actual_balance = total_charges + total_holds - total_refunds;
    let discrepancy = actual_balance - expected_balance;

    Ok(Json(serde_json::json!({
        "report_date": chrono::Utc::now().format("%Y-%m-%d").to_string(),
        "total_charges": total_charges,
        "total_holds": total_holds,
        "total_refunds": total_refunds,
        "expected_balance": expected_balance,
        "actual_balance": actual_balance,
        "discrepancy": discrepancy
    })))
}

#[get("/abnormal-flags")]
pub async fn list_abnormal_flags(pool: &State<DbPool>, user: AuthenticatedUser) -> Result<Json<Vec<AbnormalOrderFlag>>, Status> {
    user.require_permission("payments.manage")?;

    let rows = sqlx::query_as::<_, (String, Option<String>, Option<String>, String, String, bool, Option<String>, Option<chrono::NaiveDateTime>, Option<chrono::NaiveDateTime>)>(
        "SELECT id, order_id, user_id, flag_type, reason, is_cleared, cleared_by, cleared_at, created_at FROM abnormal_order_flags ORDER BY created_at DESC"
    )
    .fetch_all(pool.inner()).await.map_err(|e| { log::error!("list_abnormal_flags: select flags query failed: {}", e); Status::InternalServerError })?;

    let flags: Vec<AbnormalOrderFlag> = rows.into_iter().map(|(id, oid, uid, ft, reason, cleared, cb, cat, ca)| {
        AbnormalOrderFlag { id, order_id: oid, user_id: uid, flag_type: ft, reason, is_cleared: cleared, cleared_by: cb, cleared_at: cat, created_at: ca }
    }).collect();

    Ok(Json(flags))
}

#[post("/abnormal-flags/<flag_id>/clear")]
pub async fn clear_abnormal_flag(pool: &State<DbPool>, user: AuthenticatedUser, flag_id: String) -> Result<Status, Status> {
    user.require_permission("payments.manage")?;

    sqlx::query("UPDATE abnormal_order_flags SET is_cleared = true, cleared_by = ?, cleared_at = NOW() WHERE id = ?")
        .bind(&user.user_id).bind(&flag_id).execute(pool.inner()).await.map_err(|e| { log::error!("clear_abnormal_flag: update flag failed: {}", e); Status::InternalServerError })?;

    Ok(Status::Ok)
}

/// Generate and persist a reconciliation report for today. Idempotent — skips if today's report exists.
pub async fn generate_reconciliation_report(pool: &crate::DbPool) {
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();

    // Skip if already generated today
    let exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reconciliation_reports WHERE report_date = ?")
        .bind(&today)
        .fetch_one(pool)
        .await
        .unwrap_or(0);

    if exists > 0 {
        log::debug!("Reconciliation report for {} already exists, skipping", today);
        return;
    }

    let expected_balance: f64 = sqlx::query_scalar(
        "SELECT COALESCE(CAST(SUM(total_amount) AS DOUBLE), 0) FROM orders WHERE payment_status != 'refunded'"
    )
    .fetch_one(pool).await.unwrap_or(0.0);

    let actual_balance: f64 = sqlx::query_scalar(
        "SELECT COALESCE(CAST(SUM(CASE WHEN transaction_type = 'charge' THEN amount WHEN transaction_type = 'refund' THEN -amount ELSE 0 END) AS DOUBLE), 0) FROM payments WHERE status IN ('completed', 'refunded')"
    )
    .fetch_one(pool).await.unwrap_or(0.0);

    let discrepancy = actual_balance - expected_balance;
    let id = uuid::Uuid::new_v4().to_string();

    let _ = sqlx::query(
        "INSERT INTO reconciliation_reports (id, report_date, expected_balance, actual_balance, discrepancy, details, generated_at) VALUES (?, ?, ?, ?, ?, ?, NOW())"
    )
    .bind(&id)
    .bind(&today)
    .bind(expected_balance)
    .bind(actual_balance)
    .bind(discrepancy)
    .bind(serde_json::json!({
        "generated_by": "nightly_scheduler",
        "note": "Auto-generated daily reconciliation report"
    }).to_string())
    .execute(pool)
    .await;

    log::info!("Reconciliation report generated for {}: expected={:.2}, actual={:.2}, discrepancy={:.2}", today, expected_balance, actual_balance, discrepancy);
}
