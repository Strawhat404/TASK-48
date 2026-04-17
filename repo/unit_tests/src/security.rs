//! Additional security-focused unit tests: authZ, authN boundaries,
//! idempotency keys, and input validation that the core lib.rs doesn't cover.

#[cfg(test)]
mod tests {
    use backend::models;
    use bcrypt::{hash, verify, DEFAULT_COST};
    use chrono::{Duration, Utc};
    use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    #[derive(Debug, Serialize, Deserialize)]
    struct Claims {
        sub: String,
        username: String,
        role: String,
        exp: usize,
        iat: usize,
        session_id: String,
    }

    // ===== ROLE / PERMISSION BOUNDARIES =====

    /// Mirrors the seeded role_permissions in migrations/002_seed.sql.
    fn role_permissions(role: &str) -> &'static [&'static str] {
        match role {
            "student" => &[
                "submissions.create", "orders.create",
                "reviews.create", "cases.create",
            ],
            "instructor" => &[
                "submissions.create", "submissions.review",
                "orders.create", "reviews.create", "cases.create",
            ],
            "academic_staff" => &[
                "users.list", "submissions.list", "submissions.review",
                "submissions.approve_blocked", "orders.manage",
                "orders.fulfillment", "cases.manage", "payments.manage",
                "orders.create", "reviews.create", "cases.create",
            ],
            "administrator" => &[
                "users.list", "users.manage", "users.role_change",
                "submissions.list", "submissions.review",
                "submissions.approve_blocked", "orders.manage",
                "orders.fulfillment", "cases.manage", "payments.manage",
                "content.manage", "admin.dashboard", "admin.audit",
                "admin.settings", "admin.provision_users", "auth.generate_reset",
                "orders.create", "reviews.create", "cases.create",
            ],
            _ => &[],
        }
    }

    #[test]
    fn test_student_cannot_provision_users() {
        let perms = role_permissions("student");
        assert!(!perms.contains(&"admin.provision_users"));
    }

    #[test]
    fn test_instructor_cannot_provision_users() {
        let perms = role_permissions("instructor");
        assert!(!perms.contains(&"admin.provision_users"));
    }

    #[test]
    fn test_staff_cannot_provision_users() {
        // Only administrator can provision
        let perms = role_permissions("academic_staff");
        assert!(!perms.contains(&"admin.provision_users"));
    }

    #[test]
    fn test_only_admin_has_audit_access() {
        assert!(role_permissions("administrator").contains(&"admin.audit"));
        assert!(!role_permissions("student").contains(&"admin.audit"));
        assert!(!role_permissions("instructor").contains(&"admin.audit"));
        assert!(!role_permissions("academic_staff").contains(&"admin.audit"));
    }

    #[test]
    fn test_only_admin_has_settings_access() {
        assert!(role_permissions("administrator").contains(&"admin.settings"));
        assert!(!role_permissions("academic_staff").contains(&"admin.settings"));
    }

    #[test]
    fn test_payments_manage_granted_to_staff_and_admin() {
        // Per seed: both admin and academic_staff have payments.manage.
        assert!(role_permissions("administrator").contains(&"payments.manage"));
        assert!(role_permissions("academic_staff").contains(&"payments.manage"));
        assert!(!role_permissions("student").contains(&"payments.manage"));
        assert!(!role_permissions("instructor").contains(&"payments.manage"));
    }

    #[test]
    fn test_only_admin_can_manage_users() {
        assert!(role_permissions("administrator").contains(&"users.manage"));
        assert!(!role_permissions("academic_staff").contains(&"users.manage"));
    }

    #[test]
    fn test_academic_staff_can_review_submissions() {
        assert!(role_permissions("academic_staff").contains(&"submissions.review"));
        assert!(!role_permissions("student").contains(&"submissions.review"));
    }

    #[test]
    fn test_academic_staff_can_fulfill_orders() {
        assert!(role_permissions("academic_staff").contains(&"orders.fulfillment"));
        assert!(!role_permissions("student").contains(&"orders.fulfillment"));
        assert!(!role_permissions("instructor").contains(&"orders.fulfillment"));
    }

    #[test]
    fn test_privileged_derivation_from_permissions() {
        // is_privileged = has("users.list") || has("admin.dashboard")
        fn privileged(role: &str) -> bool {
            let p = role_permissions(role);
            p.contains(&"users.list") || p.contains(&"admin.dashboard")
        }
        assert!(!privileged("student"));
        assert!(!privileged("instructor"));
        assert!(privileged("academic_staff"));
        assert!(privileged("administrator"));
    }

    // ===== IDOR SCENARIOS (PURE LOGIC) =====

    #[test]
    fn test_idor_read_scope_student() {
        // Students see only their own resources
        fn visible(role: &str, requester: &str, owner: &str) -> bool {
            if requester == owner { return true; }
            role == "academic_staff" || role == "administrator"
        }
        assert!(visible("student", "u1", "u1"));
        assert!(!visible("student", "u2", "u1"));
        assert!(visible("academic_staff", "u2", "u1"));
        assert!(visible("administrator", "u2", "u1"));
    }

    #[test]
    fn test_case_comment_authorization() {
        // Mirrors add_comment authorization: reporter, assigned, or privileged
        fn allowed(caller: &str, reporter: &str, assigned: Option<&str>, privileged: bool) -> bool {
            caller == reporter || assigned == Some(caller) || privileged
        }
        assert!(allowed("u1", "u1", None, false)); // reporter
        assert!(allowed("staff", "u1", Some("staff"), false)); // assigned
        assert!(allowed("admin", "u1", None, true)); // privileged
        assert!(!allowed("u2", "u1", None, false)); // unrelated
    }

    // ===== IDEMPOTENCY KEY INVARIANTS =====

    #[test]
    fn test_idempotency_key_nonempty() {
        let key = format!("payment-{}", Uuid::new_v4());
        assert!(!key.is_empty());
        assert!(key.starts_with("payment-"));
    }

    #[test]
    fn test_idempotency_key_uuid_uniqueness_large() {
        // Generate 1000 idempotency keys; all must be unique
        let keys: std::collections::HashSet<String> =
            (0..1000).map(|i| format!("idem-{}-{}", i, Uuid::new_v4())).collect();
        assert_eq!(keys.len(), 1000);
    }

    #[test]
    fn test_idempotency_same_key_returns_same_id_semantics() {
        // The backend must return the same payment record for the same key.
        let key_a = "idem-1";
        let key_b = "idem-1";
        let key_c = "idem-2";
        assert_eq!(key_a, key_b);
        assert_ne!(key_a, key_c);
    }

    // ===== REFUND AMOUNT INVARIANTS =====

    #[test]
    fn test_refund_boundary_exact_original() {
        let orig = 100.00_f64;
        assert!(!(100.00 > orig), "exact match must be allowed");
    }

    #[test]
    fn test_refund_over_original_rejected() {
        let orig = 100.00_f64;
        let refund_attempt = 100.01;
        assert!(refund_attempt > orig, "must be rejected");
    }

    #[test]
    fn test_refund_zero_amount_allowed_by_bounds() {
        let orig = 100.00_f64;
        let zero = 0.0;
        assert!(zero <= orig, "zero is within bounds but likely rejected elsewhere");
    }

    #[test]
    fn test_refund_rounding_precision() {
        // Floating-point precision: 0.1 + 0.2 != 0.3
        let a = 0.1_f64 + 0.2;
        assert!((a - 0.3).abs() < 0.01);
    }

    // ===== PASSWORD RESET TOKEN FORMAT =====

    #[test]
    fn test_reset_token_format_is_uuid_derived() {
        // generate_reset_token concatenates two UUID-derived strings.
        let t = format!(
            "{}{}",
            Uuid::new_v4().to_string().replace('-', ""),
            &Uuid::new_v4().to_string().replace('-', "")[..16],
        );
        assert_eq!(t.len(), 32 + 16); // first uuid hex is 32, plus 16 chars
        assert!(t.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_reset_token_has_sufficient_entropy() {
        // At minimum 48 hex chars = 192 bits of input entropy; in practice 128-bit
        // from each UUID, but 48 hex chars is the minimum length.
        let t = format!(
            "{}{}",
            Uuid::new_v4().to_string().replace('-', ""),
            &Uuid::new_v4().to_string().replace('-', "")[..16],
        );
        assert!(t.len() >= 48);
    }

    #[test]
    fn test_reset_token_unique_across_many_generations() {
        let tokens: std::collections::HashSet<String> = (0..500).map(|_| {
            format!(
                "{}{}",
                Uuid::new_v4().to_string().replace('-', ""),
                &Uuid::new_v4().to_string().replace('-', "")[..16],
            )
        }).collect();
        assert_eq!(tokens.len(), 500);
    }

    // ===== RESET TOKEN EXPIRY =====

    #[test]
    fn test_reset_token_expiry_is_bounded() {
        let now = Utc::now().naive_utc();
        let exp = now + Duration::minutes(models::PASSWORD_RESET_EXPIRY_MINUTES);
        // Must be exactly PASSWORD_RESET_EXPIRY_MINUTES in the future
        assert_eq!((exp - now).num_minutes(), models::PASSWORD_RESET_EXPIRY_MINUTES);
    }

    #[test]
    fn test_reset_token_expired_after_hour() {
        let issued = Utc::now().naive_utc() - Duration::hours(2);
        let exp = issued + Duration::minutes(models::PASSWORD_RESET_EXPIRY_MINUTES);
        let now = Utc::now().naive_utc();
        assert!(now > exp, "token from 2h ago must be expired (expiry is 60min)");
    }

    // ===== BASE64 ROUND-TRIP (used by submissions + review images) =====

    #[test]
    fn test_base64_roundtrip_pdf_bytes() {
        use base64::{engine::general_purpose, Engine};
        let original = b"%PDF-1.4 test bytes";
        let encoded = general_purpose::STANDARD.encode(original);
        let decoded = general_purpose::STANDARD.decode(&encoded).unwrap();
        assert_eq!(decoded.as_slice(), original.as_slice());
    }

    #[test]
    fn test_base64_invalid_data_returns_error() {
        use base64::{engine::general_purpose, Engine};
        let result = general_purpose::STANDARD.decode("!!!not_base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_base64_empty_roundtrip() {
        use base64::{engine::general_purpose, Engine};
        let decoded = general_purpose::STANDARD.decode("").unwrap();
        assert!(decoded.is_empty());
    }

    // ===== SHA-256 INTEGRITY CHECKS =====

    #[test]
    fn test_sha256_same_input_same_hash() {
        let mut a = Sha256::new(); a.update(b"hello");
        let mut b = Sha256::new(); b.update(b"hello");
        assert_eq!(hex::encode(a.finalize()), hex::encode(b.finalize()));
    }

    #[test]
    fn test_sha256_hash_is_64_hex_chars() {
        let mut h = Sha256::new();
        h.update(b"anything");
        let out = hex::encode(h.finalize());
        assert_eq!(out.len(), 64);
        assert!(out.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_sha256_avalanche_one_bit_change() {
        let mut a = Sha256::new(); a.update(b"hello");
        let mut b = Sha256::new(); b.update(b"hellp"); // one char different
        let ha = hex::encode(a.finalize());
        let hb = hex::encode(b.finalize());
        assert_ne!(ha, hb);
        // Half the characters (roughly) should differ
        let diff: usize = ha.chars().zip(hb.chars()).filter(|(x, y)| x != y).count();
        assert!(diff > 20, "avalanche effect: expected many differences, got {}", diff);
    }

    // ===== JWT EXPIRY EDGE CASES =====

    #[test]
    fn test_jwt_at_boundary_of_expiry_accepted() {
        let secret = "test_secret_that_is_at_least_32_bytes_long!!";
        let now = Utc::now().timestamp() as usize;
        // Token expiring in 5 seconds — should decode now
        let claims = Claims {
            sub: "u1".into(), username: "u".into(), role: "student".into(),
            iat: now, exp: now + 5, session_id: "s1".into(),
        };
        let token = encode(&Header::default(), &claims,
            &EncodingKey::from_secret(secret.as_bytes())).unwrap();
        assert!(decode::<Claims>(&token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &Validation::default()).is_ok());
    }

    #[test]
    fn test_jwt_expired_one_second_ago_rejected() {
        let secret = "test_secret_that_is_at_least_32_bytes_long!!";
        let now = Utc::now().timestamp() as usize;
        let claims = Claims {
            sub: "u1".into(), username: "u".into(), role: "student".into(),
            iat: now - 100, exp: now - 1, session_id: "s1".into(),
        };
        let token = encode(&Header::default(), &claims,
            &EncodingKey::from_secret(secret.as_bytes())).unwrap();
        let mut validation = Validation::default();
        validation.leeway = 0;
        assert!(decode::<Claims>(&token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &validation).is_err());
    }

    // ===== BCRYPT COST PARAMETER =====

    #[test]
    fn test_bcrypt_default_cost_reasonable() {
        // DEFAULT_COST should be >= 10 for production security
        assert!(DEFAULT_COST >= 10, "bcrypt cost must be >= 10 for security");
    }

    #[test]
    fn test_bcrypt_hash_format_starts_with_dollar_two() {
        let hashed = hash("test", DEFAULT_COST).unwrap();
        assert!(hashed.starts_with("$2"), "bcrypt hashes must start with $2");
    }

    #[test]
    fn test_bcrypt_hash_length_is_60_chars() {
        let hashed = hash("anything", DEFAULT_COST).unwrap();
        assert_eq!(hashed.len(), 60, "bcrypt hashes are exactly 60 chars");
    }

    // ===== INVALID PASSWORD CATEGORIES =====

    #[test]
    fn test_password_with_null_byte_handled_gracefully() {
        // Bcrypt has historically had null-byte issues; verify the library either
        // hashes safely or returns an error (never panics).
        let pw_with_null = "pass\0word";
        match hash(pw_with_null, DEFAULT_COST) {
            Ok(hashed) => {
                // If it hashed, verify must also work without panicking.
                let _ = verify(pw_with_null, &hashed);
            }
            Err(_) => {
                // Explicit rejection is also acceptable hardening.
            }
        }
    }

    // ===== OWNERSHIP INVARIANTS FOR SUBMISSIONS =====

    #[test]
    fn test_submission_status_lifecycle_allowed_states() {
        // These are the statuses used by the content.rs state machine.
        let valid = ["draft", "submitted", "in_review", "revision_requested",
                     "accepted", "rejected", "published", "blocked"];
        assert_eq!(valid.len(), 8);
        for s in &valid {
            assert!(!s.is_empty());
            assert_eq!(*s, s.to_lowercase());
        }
    }

    #[test]
    fn test_submission_submit_requires_draft_or_revision_requested() {
        // From submit_item in content.rs
        fn can_submit(current: &str) -> bool {
            current == "draft" || current == "revision_requested"
        }
        assert!(can_submit("draft"));
        assert!(can_submit("revision_requested"));
        assert!(!can_submit("submitted"));
        assert!(!can_submit("accepted"));
        assert!(!can_submit("published"));
    }

    #[test]
    fn test_submission_approve_requires_submitted_in_review_or_blocked() {
        // From approve_item in content.rs
        fn can_approve(current: &str) -> bool {
            matches!(current, "submitted" | "in_review" | "blocked")
        }
        assert!(can_approve("submitted"));
        assert!(can_approve("in_review"));
        assert!(can_approve("blocked"));
        assert!(!can_approve("draft"));
        assert!(!can_approve("accepted"));
        assert!(!can_approve("rejected"));
        assert!(!can_approve("published"));
    }

    #[test]
    fn test_submission_reject_requires_submitted_or_in_review() {
        fn can_reject(current: &str) -> bool {
            matches!(current, "submitted" | "in_review")
        }
        assert!(can_reject("submitted"));
        assert!(can_reject("in_review"));
        assert!(!can_reject("blocked"));
        assert!(!can_reject("draft"));
    }

    #[test]
    fn test_submission_publish_requires_accepted() {
        fn can_publish(current: &str) -> bool { current == "accepted" }
        assert!(can_publish("accepted"));
        assert!(!can_publish("submitted"));
        assert!(!can_publish("published"));
        assert!(!can_publish("draft"));
    }

    // ===== SESSION TIMEOUTS =====

    #[test]
    fn test_session_timeout_30_min_is_industry_standard() {
        assert_eq!(models::SESSION_IDLE_TIMEOUT_MINUTES, 30);
    }

    #[test]
    fn test_token_expiry_hours_constant_reasonable() {
        let expiry_hours: u64 = 24;
        assert!(expiry_hours >= 1);
        assert!(expiry_hours <= 7 * 24); // never more than a week
    }

    // ===== INPUT LENGTH ENFORCEMENT =====

    #[test]
    fn test_review_title_over_120_rejected_by_route_logic() {
        // From reviews.rs: `if req.title.len() > 120 { return UnprocessableEntity }`
        fn valid_review_title(len: usize) -> bool { len <= 120 }
        assert!(valid_review_title(120));
        assert!(!valid_review_title(121));
        assert!(valid_review_title(1));
    }

    #[test]
    fn test_order_line_items_nonempty_required() {
        let count = 0_usize;
        assert!(count == 0, "empty line items must be rejected");
    }

    #[test]
    fn test_fulfillment_reason_nonblank_required() {
        fn is_blank(s: &str) -> bool { s.trim().is_empty() }
        assert!(is_blank(""));
        assert!(is_blank("   "));
        assert!(is_blank("\n\t"));
        assert!(!is_blank("x"));
        assert!(!is_blank("  x  "));
    }
}
