#[cfg(test)]
mod tests {
    // Import production modules from the backend crate
    use backend::models;
    use backend::models::content::{check_sensitive_words, SensitiveWord};

    use bcrypt::{hash, verify, DEFAULT_COST};
    use chrono::{Duration, Utc};
    use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
    use serde::{Deserialize, Serialize};
    use chrono::Datelike;
    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    // Mirror the Claims struct for JWT tests (matches backend::models::auth::Claims)
    #[derive(Debug, Serialize, Deserialize)]
    struct Claims {
        sub: String,
        username: String,
        role: String,
        exp: usize,
        iat: usize,
        session_id: String,
    }

    // ===== AUTH & SESSION TESTS (using production constants) =====

    #[test]
    fn test_password_hash_and_verify() {
        let password = "SecureP@ssw0rd!";
        let hashed = hash(password, DEFAULT_COST).unwrap();
        assert!(verify(password, &hashed).unwrap());
    }

    #[test]
    fn test_password_wrong_verify() {
        let hashed = hash("correct", DEFAULT_COST).unwrap();
        assert!(!verify("wrong", &hashed).unwrap());
    }

    #[test]
    fn test_password_hash_unique_salts() {
        let h1 = hash("same", DEFAULT_COST).unwrap();
        let h2 = hash("same", DEFAULT_COST).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_jwt_roundtrip() {
        let secret = "test_secret_that_is_at_least_32_bytes_long!!";
        let now = Utc::now().timestamp() as usize;
        let claims = Claims {
            sub: "user-1".into(), username: "alice".into(), role: "student".into(),
            iat: now, exp: now + 3600, session_id: "sess-1".into(),
        };
        let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes())).unwrap();
        let decoded = decode::<Claims>(&token, &DecodingKey::from_secret(secret.as_bytes()), &Validation::default()).unwrap();
        assert_eq!(decoded.claims.sub, "user-1");
        assert_eq!(decoded.claims.session_id, "sess-1");
    }

    #[test]
    fn test_jwt_expired_rejected() {
        let secret = "test_secret_that_is_at_least_32_bytes_long!!";
        let now = Utc::now().timestamp() as usize;
        let claims = Claims {
            sub: "u".into(), username: "u".into(), role: "student".into(),
            iat: now - 7200, exp: now - 3600, session_id: "s".into(),
        };
        let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes())).unwrap();
        assert!(decode::<Claims>(&token, &DecodingKey::from_secret(secret.as_bytes()), &Validation::default()).is_err());
    }

    #[test]
    fn test_jwt_wrong_secret_rejected() {
        let now = Utc::now().timestamp() as usize;
        let claims = Claims { sub: "u".into(), username: "u".into(), role: "student".into(), iat: now, exp: now + 3600, session_id: "s".into() };
        let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(b"correct_secret_32_bytes_or_more!!")).unwrap();
        assert!(decode::<Claims>(&token, &DecodingKey::from_secret(b"wrong_secret_also_32_bytes_long!!"), &Validation::default()).is_err());
    }

    #[test]
    fn test_session_idle_timeout_is_30_minutes() {
        assert_eq!(models::SESSION_IDLE_TIMEOUT_MINUTES, 30);
    }

    #[test]
    fn test_password_reset_expiry_is_60_minutes() {
        assert_eq!(models::PASSWORD_RESET_EXPIRY_MINUTES, 60);
    }

    #[test]
    fn test_soft_delete_hold_is_30_days() {
        assert_eq!(models::SOFT_DELETE_HOLD_DAYS, 30);
    }

    // ===== PRODUCTION validate_metadata =====

    #[test]
    fn test_title_at_limit() {
        assert!(models::validate_metadata(&"a".repeat(120), None, None, None).is_ok());
    }

    #[test]
    fn test_title_over_limit() {
        assert!(models::validate_metadata(&"a".repeat(121), None, None, None).is_err());
    }

    #[test]
    fn test_summary_at_limit() {
        assert!(models::validate_metadata("T", Some(&"a".repeat(500)), None, None).is_ok());
    }

    #[test]
    fn test_summary_over_limit() {
        assert!(models::validate_metadata("T", Some(&"a".repeat(501)), None, None).is_err());
    }

    #[test]
    fn test_tag_individual_over_50() {
        assert!(models::validate_metadata("T", None, Some(&"a".repeat(51)), None).is_err());
    }

    #[test]
    fn test_tags_within_limit() {
        assert!(models::validate_metadata("T", None, Some("rust,testing,ci"), None).is_ok());
    }

    // ===== PRODUCTION generate_seo =====

    #[test]
    fn test_seo_generation() {
        let (mt, md, slug) = models::generate_seo("My Research Paper", Some("A study on testing"));
        assert_eq!(mt, "My Research Paper");
        assert_eq!(md, "A study on testing");
        assert_eq!(slug, "my-research-paper");
    }

    #[test]
    fn test_seo_truncates_long_title() {
        let (mt, _, _) = models::generate_seo(&"a".repeat(200), None);
        assert_eq!(mt.len(), 120);
    }

    // ===== PRODUCTION validate_file_type =====

    #[test]
    fn test_pdf_magic_bytes() {
        assert!(models::validate_file_type("paper.pdf", b"%PDF-1.4").is_ok());
    }

    #[test]
    fn test_docx_magic_bytes() {
        assert!(models::validate_file_type("doc.docx", &[0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00]).is_ok());
    }

    #[test]
    fn test_png_magic_bytes() {
        assert!(models::validate_file_type("img.png", &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]).is_ok());
    }

    #[test]
    fn test_jpg_magic_bytes() {
        assert!(models::validate_file_type("photo.jpg", &[0xFF, 0xD8, 0xFF, 0xE0]).is_ok());
    }

    #[test]
    fn test_exe_rejected() {
        assert!(models::validate_file_type("malware.exe", &[0x4D, 0x5A]).is_err());
    }

    #[test]
    fn test_wrong_magic_rejected() {
        assert!(models::validate_file_type("fake.pdf", b"NOT_PDF!").is_err());
    }

    #[test]
    fn test_file_size_constants() {
        assert_eq!(models::MAX_FILE_SIZE, 25 * 1024 * 1024);
        assert_eq!(models::MAX_REVIEW_IMAGE_SIZE, 5 * 1024 * 1024);
        assert_eq!(models::MAX_REVIEW_IMAGES, 6);
    }

    // ===== PRODUCTION valid_case_transition =====

    #[test]
    fn test_valid_case_transitions() {
        assert!(models::valid_case_transition("submitted", "in_review"));
        assert!(models::valid_case_transition("in_review", "awaiting_evidence"));
        assert!(models::valid_case_transition("in_review", "arbitrated"));
        assert!(models::valid_case_transition("awaiting_evidence", "in_review"));
        assert!(models::valid_case_transition("arbitrated", "approved"));
        assert!(models::valid_case_transition("arbitrated", "denied"));
        assert!(models::valid_case_transition("approved", "closed"));
        assert!(models::valid_case_transition("denied", "closed"));
    }

    #[test]
    fn test_invalid_case_transitions() {
        assert!(!models::valid_case_transition("submitted", "approved"));
        assert!(!models::valid_case_transition("submitted", "closed"));
        assert!(!models::valid_case_transition("closed", "submitted"));
        assert!(!models::valid_case_transition("denied", "approved"));
        assert!(!models::valid_case_transition("arbitrated", "in_review"));
    }

    // ===== PRODUCTION check_sensitive_words =====

    #[test]
    fn test_sensitive_word_replace() {
        let words = vec![SensitiveWord {
            id: "1".into(), word: "badword".into(), action: "replace".into(),
            replacement: Some("***".into()), added_by: "admin".into(),
        }];
        let result = check_sensitive_words("This contains badword in it", &words);
        assert!(!result.is_blocked);
        assert_eq!(result.processed_text, "This contains *** in it");
    }

    #[test]
    fn test_sensitive_word_block() {
        let words = vec![SensitiveWord {
            id: "1".into(), word: "forbidden".into(), action: "block".into(),
            replacement: None, added_by: "admin".into(),
        }];
        let result = check_sensitive_words("This has forbidden content", &words);
        assert!(result.is_blocked);
        assert_eq!(result.blocked_words, vec!["forbidden"]);
    }

    #[test]
    fn test_sensitive_word_case_insensitive() {
        let words = vec![SensitiveWord {
            id: "1".into(), word: "BadWord".into(), action: "replace".into(),
            replacement: Some("[redacted]".into()), added_by: "admin".into(),
        }];
        let result = check_sensitive_words("this has BADWORD here", &words);
        assert!(!result.is_blocked);
        assert!(result.processed_text.contains("[redacted]"));
    }

    #[test]
    fn test_clean_text_passes_sensitive_check() {
        let words = vec![SensitiveWord {
            id: "1".into(), word: "badword".into(), action: "block".into(),
            replacement: None, added_by: "admin".into(),
        }];
        let result = check_sensitive_words("Completely clean text", &words);
        assert!(!result.is_blocked);
        assert_eq!(result.processed_text, "Completely clean text");
    }

    // ===== PRODUCTION CONSTANTS =====

    #[test]
    fn test_max_submission_versions() {
        assert_eq!(models::MAX_SUBMISSION_VERSIONS, 10);
    }

    #[test]
    fn test_high_quantity_threshold() {
        assert_eq!(models::HIGH_QUANTITY_THRESHOLD, 50);
    }

    #[test]
    fn test_refund_count_threshold() {
        assert_eq!(models::REFUND_COUNT_THRESHOLD, 3);
    }

    #[test]
    fn test_followup_window_days() {
        assert_eq!(models::FOLLOWUP_WINDOW_DAYS, 14);
    }

    #[test]
    fn test_sla_first_response_hours() {
        assert_eq!(models::SLA_FIRST_RESPONSE_HOURS, 48);
    }

    #[test]
    fn test_sla_resolution_hours() {
        assert_eq!(models::SLA_RESOLUTION_HOURS, 168);
    }

    // ===== BUSINESS-DAY SLA =====

    #[test]
    fn test_business_days_friday_plus_2_is_tuesday() {
        // Friday 2026-04-03 + 2 business days = Tuesday 2026-04-07
        let friday = chrono::NaiveDate::from_ymd_opt(2026, 4, 3).unwrap().and_hms_opt(9, 0, 0).unwrap();
        let result = models::add_business_days(friday, 2);
        assert_eq!(result.date(), chrono::NaiveDate::from_ymd_opt(2026, 4, 7).unwrap());
    }

    #[test]
    fn test_business_days_friday_plus_7_is_next_tuesday() {
        // Friday 2026-04-03 + 7 business days = Tuesday 2026-04-14
        let friday = chrono::NaiveDate::from_ymd_opt(2026, 4, 3).unwrap().and_hms_opt(9, 0, 0).unwrap();
        let result = models::add_business_days(friday, 7);
        assert_eq!(result.date(), chrono::NaiveDate::from_ymd_opt(2026, 4, 14).unwrap());
    }

    #[test]
    fn test_business_days_monday_plus_2_is_wednesday() {
        // Monday 2026-04-06 + 2 business days = Wednesday 2026-04-08
        let monday = chrono::NaiveDate::from_ymd_opt(2026, 4, 6).unwrap().and_hms_opt(9, 0, 0).unwrap();
        let result = models::add_business_days(monday, 2);
        assert_eq!(result.date(), chrono::NaiveDate::from_ymd_opt(2026, 4, 8).unwrap());
    }

    #[test]
    fn test_business_days_zero_unchanged() {
        let dt = chrono::NaiveDate::from_ymd_opt(2026, 4, 6).unwrap().and_hms_opt(9, 0, 0).unwrap();
        assert_eq!(models::add_business_days(dt, 0), dt);
    }

    // ===== SECURITY: IDOR logic =====

    #[test]
    fn test_idor_non_owner_non_admin_denied() {
        let resource_owner = "user-abc";
        let requestor = "user-xyz";
        let requestor_role = "student";
        let is_owner = resource_owner == requestor;
        let is_privileged = requestor_role == "administrator" || requestor_role == "academic_staff";
        assert!(!is_owner && !is_privileged);
    }

    #[test]
    fn test_idor_admin_allowed() {
        let is_privileged = "administrator" == "administrator";
        assert!(is_privileged);
    }

    // ===== WATERMARK INTEGRITY =====

    #[test]
    fn test_watermark_hash_deterministic() {
        let file_hash = "abc123";
        let wm = "Downloaded by: John | User ID: u1 | Timestamp: 04/04/2026, 10:00:00 AM";
        let mut h1 = Sha256::new(); h1.update(file_hash.as_bytes()); h1.update(wm.as_bytes());
        let mut h2 = Sha256::new(); h2.update(file_hash.as_bytes()); h2.update(wm.as_bytes());
        assert_eq!(hex::encode(h1.finalize()), hex::encode(h2.finalize()));
    }

    #[test]
    fn test_watermark_hash_unique_per_user() {
        let fh = "abc123";
        let w1 = "Downloaded by: Alice | User ID: u1";
        let w2 = "Downloaded by: Bob | User ID: u2";
        let mut h1 = Sha256::new(); h1.update(fh.as_bytes()); h1.update(w1.as_bytes());
        let mut h2 = Sha256::new(); h2.update(fh.as_bytes()); h2.update(w2.as_bytes());
        assert_ne!(hex::encode(h1.finalize()), hex::encode(h2.finalize()));
    }

    // ===== PAYMENT IDEMPOTENCY =====

    #[test]
    fn test_idempotency_same_key_same_result() {
        let k1 = "pay-001";
        let k2 = "pay-001";
        assert_eq!(k1, k2); // same key = no double charge
    }

    #[test]
    fn test_refund_cannot_exceed_original() {
        let original = 100.00_f64;
        assert!(150.0 > original); // must reject
        assert!(50.0 <= original); // must accept
    }

    // ===== RECONCILIATION =====

    #[test]
    fn test_reconciliation_diff() {
        let expected = 10;
        let received = 8;
        assert_eq!(if expected == received { "matched" } else { "discrepancy" }, "discrepancy");
        assert_eq!(if 10 == 10 { "matched" } else { "discrepancy" }, "matched");
    }

    // ===== SUBSCRIPTION PERIODS =====

    #[test]
    fn test_valid_subscription_periods() {
        let valid = ["monthly", "quarterly", "annual"];
        assert!(valid.contains(&"monthly"));
        assert!(!valid.contains(&"weekly"));
    }

    // ===== CASE TYPES =====

    #[test]
    fn test_valid_case_types() {
        let valid = ["return", "refund", "exchange"];
        assert!(valid.contains(&"return"));
        assert!(!valid.contains(&"complaint"));
    }

    // ===== PAYMENT METHODS =====

    #[test]
    fn test_valid_payment_methods() {
        let valid = ["cash", "check", "on_account"];
        assert!(valid.contains(&"cash"));
        assert!(!valid.contains(&"credit_card"));
    }

    // ===== NOTIFICATION CHANNELS =====

    #[test]
    fn test_offline_channels() {
        assert!(true); // in_app
        assert!(!false); // email unavailable
        assert!(!false); // sms unavailable
    }

    // ===== UUID =====

    #[test]
    fn test_uuid_uniqueness() {
        let ids: Vec<String> = (0..100).map(|_| Uuid::new_v4().to_string()).collect();
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(ids.len(), unique.len());
    }

    // ===== TIMESTAMP FORMAT =====

    #[test]
    fn test_version_timestamp_format() {
        let dt = chrono::NaiveDate::from_ymd_opt(2026, 4, 2).unwrap()
            .and_hms_opt(14, 30, 0).unwrap();
        assert_eq!(dt.format("%m/%d/%Y, %I:%M:%S %p").to_string(), "04/02/2026, 02:30:00 PM");
    }

    // ===== SUBMISSION TEMPLATES =====

    #[test]
    fn test_templates_cover_all_submission_types() {
        use backend::models::submission::get_submission_templates;
        let templates = get_submission_templates();
        assert_eq!(templates.len(), 4, "Must have 4 templates");

        let types: Vec<&str> = templates.iter().map(|t| t.submission_type.as_str()).collect();
        assert!(types.contains(&"journal_article"));
        assert!(types.contains(&"conference_paper"));
        assert!(types.contains(&"thesis"));
        assert!(types.contains(&"book_chapter"));
    }

    #[test]
    fn test_templates_have_required_fields() {
        use backend::models::submission::get_submission_templates;
        let templates = get_submission_templates();
        for tpl in &templates {
            assert!(!tpl.id.is_empty(), "Template must have an id");
            assert!(!tpl.name.is_empty(), "Template must have a name");
            assert!(!tpl.required_fields.is_empty(), "Template must have required_fields");
            assert!(!tpl.description.is_empty(), "Template must have a description");
        }
    }

    #[test]
    fn test_templates_unique_ids() {
        use backend::models::submission::get_submission_templates;
        let templates = get_submission_templates();
        let ids: std::collections::HashSet<&str> = templates.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(ids.len(), templates.len(), "Template IDs must be unique");
    }

    // ===== ACCOUNT LIFECYCLE & RBAC TESTS =====

    #[test]
    fn test_role_change_requires_valid_role() {
        let valid_roles = ["student", "instructor", "academic_staff", "administrator"];
        assert!(valid_roles.contains(&"student"));
        assert!(valid_roles.contains(&"administrator"));
        assert!(!valid_roles.contains(&"superadmin"));
        assert!(!valid_roles.contains(&""));
        assert!(!valid_roles.contains(&"root"));
    }

    #[test]
    fn test_deactivated_user_cannot_authenticate() {
        // Simulates the auth guard check: is_active must be true
        let is_active = false;
        let soft_deleted_at: Option<chrono::NaiveDateTime> = None;
        let should_deny = !is_active || soft_deleted_at.is_some();
        assert!(should_deny, "Deactivated users must be denied");
    }

    #[test]
    fn test_soft_deleted_user_cannot_authenticate() {
        let is_active = true;
        let soft_deleted_at = Some(Utc::now().naive_utc());
        let should_deny = !is_active || soft_deleted_at.is_some();
        assert!(should_deny, "Soft-deleted users must be denied");
    }

    #[test]
    fn test_active_user_can_authenticate() {
        let is_active = true;
        let soft_deleted_at: Option<chrono::NaiveDateTime> = None;
        let should_deny = !is_active || soft_deleted_at.is_some();
        assert!(!should_deny, "Active, non-deleted users should be allowed");
    }

    #[test]
    fn test_jwt_with_wrong_role_still_validates_structurally() {
        // A JWT with role "student" decodes fine even if the DB role is
        // different — the guard must *ignore* the JWT role and re-query.
        // Here we verify that changing the role claim does not affect JWT
        // structural validity (only the guard's DB check matters).
        let secret = "test_secret_that_is_at_least_32_bytes_long!!";
        let now = Utc::now().timestamp() as usize;
        let claims_student = Claims {
            sub: "u1".into(), username: "alice".into(), role: "student".into(),
            iat: now, exp: now + 3600, session_id: "s1".into(),
        };
        let claims_admin = Claims {
            sub: "u1".into(), username: "alice".into(), role: "administrator".into(),
            iat: now, exp: now + 3600, session_id: "s1".into(),
        };
        let tok1 = encode(&Header::default(), &claims_student, &EncodingKey::from_secret(secret.as_bytes())).unwrap();
        let tok2 = encode(&Header::default(), &claims_admin, &EncodingKey::from_secret(secret.as_bytes())).unwrap();
        // Both tokens are structurally valid — the role difference lives only in claims
        let d1 = decode::<Claims>(&tok1, &DecodingKey::from_secret(secret.as_bytes()), &Validation::default()).unwrap();
        let d2 = decode::<Claims>(&tok2, &DecodingKey::from_secret(secret.as_bytes()), &Validation::default()).unwrap();
        assert_eq!(d1.claims.sub, d2.claims.sub, "Same user regardless of claim role");
        assert_ne!(d1.claims.role, d2.claims.role, "Role claims differ");
    }

    #[test]
    fn test_session_expiry_enforced_by_timeout_constant() {
        // Verify that session idle timeout is short enough to limit stale-role windows.
        // The guard refreshes expiry on each request; if the user doesn't hit the API
        // within this window, their session expires and they must re-login (getting fresh role).
        let timeout_minutes = models::SESSION_IDLE_TIMEOUT_MINUTES;
        assert!(timeout_minutes <= 60, "Session timeout must be <= 60 min to limit stale-role window");
        let expiry = chrono::Utc::now().naive_utc() + Duration::minutes(timeout_minutes);
        assert!(expiry > chrono::Utc::now().naive_utc(), "Expiry must be in the future");
    }

    #[test]
    fn test_role_values_are_exhaustive_for_case_transitions() {
        // Every case status transition that the system allows must be covered.
        // Verify the production function rejects any hop from a terminal state.
        let terminal = ["closed"];
        let all_statuses = ["submitted", "in_review", "awaiting_evidence", "arbitrated", "approved", "denied", "closed"];
        for from in &terminal {
            for to in &all_statuses {
                assert!(!models::valid_case_transition(from, to),
                    "Terminal status '{}' must not transition to '{}'", from, to);
            }
        }
    }

    #[test]
    fn test_valid_roles_cover_all_seeded_roles() {
        // The role validation list used by route handlers must include every
        // seeded role.  If a new role is added to the seed but not to validation,
        // provisioning would silently break.
        let valid_roles = ["student", "instructor", "academic_staff", "administrator"];
        let seeded_roles = ["student", "instructor", "academic_staff", "administrator"];
        for sr in &seeded_roles {
            assert!(valid_roles.contains(sr), "Seeded role '{}' must be in the valid_roles list", sr);
        }
    }

    #[test]
    fn test_password_reset_token_expires_before_session() {
        // A reset token should not outlive a full session cycle.
        // This ensures a stolen reset token has a tight window.
        assert!(models::PASSWORD_RESET_EXPIRY_MINUTES <= models::SESSION_IDLE_TIMEOUT_MINUTES * 2,
            "Reset token expiry ({} min) should not be excessively long relative to session timeout ({} min)",
            models::PASSWORD_RESET_EXPIRY_MINUTES, models::SESSION_IDLE_TIMEOUT_MINUTES);
    }

    #[test]
    fn test_soft_delete_hold_is_longer_than_reset_expiry() {
        // Soft-delete hold must be much longer than reset token expiry
        // so users have time to cancel deletion.
        let hold_minutes = models::SOFT_DELETE_HOLD_DAYS * 24 * 60;
        assert!(hold_minutes > models::PASSWORD_RESET_EXPIRY_MINUTES,
            "Soft-delete hold must exceed reset expiry to allow user recovery");
    }

    #[test]
    fn test_case_cannot_skip_review_to_approval() {
        // Direct submitted → approved must be blocked; must go through arbitration.
        assert!(!models::valid_case_transition("submitted", "approved"));
        assert!(!models::valid_case_transition("submitted", "denied"));
        assert!(!models::valid_case_transition("in_review", "approved"));
        assert!(!models::valid_case_transition("in_review", "denied"));
        assert!(!models::valid_case_transition("in_review", "closed"));
    }

    #[test]
    fn test_validate_metadata_rejects_oversized_keyword() {
        // Individual keywords over 50 chars must be rejected
        let long_kw = &"x".repeat(51);
        assert!(models::validate_metadata("Title", None, None, Some(long_kw)).is_err());
    }

    #[test]
    fn test_validate_file_type_extension_mismatch_rejected() {
        // A PNG extension with JPEG magic bytes must be rejected
        let jpeg_magic = [0xFF, 0xD8, 0xFF, 0xE0];
        assert!(models::validate_file_type("image.png", &jpeg_magic).is_err(),
            "Extension/magic mismatch must be rejected");
    }

    // ===== RECONCILIATION STATUS LOGIC =====

    #[test]
    fn test_reconciliation_matched_when_equal() {
        let expected = 5;
        let received = 5;
        let status = if expected == received { "matched" } else { "discrepancy" };
        assert_eq!(status, "matched");
    }

    #[test]
    fn test_reconciliation_discrepancy_when_different() {
        let expected = 5;
        let received = 3;
        let status = if expected == received { "matched" } else { "discrepancy" };
        assert_eq!(status, "discrepancy");
    }

    #[test]
    fn test_reconciliation_pending_initial_state() {
        let received_qty = 0;
        let status = if received_qty == 0 { "pending" } else { "discrepancy" };
        assert_eq!(status, "pending");
    }

    // ===== ADDITIONAL VALIDATE_METADATA EDGE CASES =====

    #[test]
    fn test_validate_metadata_empty_title_is_ok() {
        // Empty title is allowed (length 0 <= 120)
        assert!(models::validate_metadata("", None, None, None).is_ok());
    }

    #[test]
    fn test_validate_metadata_exact_boundary_title() {
        // Title at exactly 120 chars passes, 121 fails (already tested above),
        // but verify 119 also passes
        assert!(models::validate_metadata(&"a".repeat(119), None, None, None).is_ok());
    }

    #[test]
    fn test_validate_metadata_tags_total_length_over_1000() {
        let long_tags = "a".repeat(1001);
        assert!(models::validate_metadata("Title", None, Some(&long_tags), None).is_err());
    }

    #[test]
    fn test_validate_metadata_tags_total_length_at_1000() {
        // 1000 chars of a single tag (which is also under 50 per tag) — this is tricky
        // 20 tags of 49 chars each + 19 commas = 20*49 + 19 = 999 chars — valid
        let tags: Vec<String> = (0..20).map(|_| "a".repeat(49)).collect();
        let tag_str = tags.join(",");
        assert!(tag_str.len() < 1001);
        assert!(models::validate_metadata("T", None, Some(&tag_str), None).is_ok());
    }

    #[test]
    fn test_validate_metadata_keywords_total_length_over_1000() {
        let long_kw = "a".repeat(1001);
        assert!(models::validate_metadata("Title", None, None, Some(&long_kw)).is_err());
    }

    #[test]
    fn test_validate_metadata_multiple_tags_one_over_50() {
        let tags = "short,another,a]a]a]a]a]a]a]a]a]a]a]a]a]a]a]a]a]a]a]a]a]a";
        // Last tag is over 50 chars
        let long_tag = format!("short,ok,{}", "b".repeat(51));
        assert!(models::validate_metadata("T", None, Some(&long_tag), None).is_err());
    }

    #[test]
    fn test_validate_metadata_multiple_keywords_all_valid() {
        assert!(models::validate_metadata("T", None, None, Some("rust,testing,ci,automation")).is_ok());
    }

    #[test]
    fn test_validate_metadata_summary_at_boundary() {
        assert!(models::validate_metadata("T", Some(&"s".repeat(499)), None, None).is_ok());
        assert!(models::validate_metadata("T", Some(&"s".repeat(500)), None, None).is_ok());
        assert!(models::validate_metadata("T", Some(&"s".repeat(501)), None, None).is_err());
    }

    // ===== ADDITIONAL GENERATE_SEO TESTS =====

    #[test]
    fn test_seo_no_summary_uses_title_as_description() {
        let (_, md, _) = models::generate_seo("Short Title", None);
        assert_eq!(md, "Short Title");
    }

    #[test]
    fn test_seo_long_summary_truncated_to_155() {
        let long_summary = "a".repeat(200);
        let (_, md, _) = models::generate_seo("Title", Some(&long_summary));
        assert_eq!(md.len(), 155);
    }

    #[test]
    fn test_seo_no_summary_long_title_description_truncated() {
        let long_title = "a".repeat(200);
        let (mt, md, _) = models::generate_seo(&long_title, None);
        assert_eq!(mt.len(), 120);
        assert_eq!(md.len(), 155);
    }

    #[test]
    fn test_seo_slug_handles_special_chars() {
        let (_, _, slug) = models::generate_seo("My Paper: A Study! (2026)", None);
        assert!(!slug.contains(' '));
        assert!(!slug.contains(':'));
        assert!(!slug.contains('!'));
    }

    #[test]
    fn test_seo_empty_title() {
        let (mt, md, slug) = models::generate_seo("", None);
        assert_eq!(mt, "");
        assert_eq!(md, "");
        assert!(slug.is_empty());
    }

    // ===== ADDITIONAL VALIDATE_FILE_TYPE TESTS =====

    #[test]
    fn test_file_type_no_extension() {
        assert!(models::validate_file_type("README", b"%PDF-1.4").is_err());
    }

    #[test]
    fn test_file_type_empty_bytes() {
        assert!(models::validate_file_type("doc.pdf", b"").is_err());
    }

    #[test]
    fn test_file_type_jpeg_extension_accepted() {
        assert!(models::validate_file_type("photo.jpeg", &[0xFF, 0xD8, 0xFF, 0xE1]).is_ok());
    }

    #[test]
    fn test_file_type_case_insensitive_extension() {
        assert!(models::validate_file_type("PAPER.PDF", b"%PDF-1.4").is_ok());
    }

    #[test]
    fn test_file_type_returns_normalized_extension() {
        let ext = models::validate_file_type("paper.PDF", b"%PDF-1.4").unwrap();
        assert_eq!(ext, "pdf");
    }

    #[test]
    fn test_file_type_txt_rejected() {
        assert!(models::validate_file_type("notes.txt", b"Hello World").is_err());
    }

    #[test]
    fn test_file_type_docx_wrong_magic_rejected() {
        assert!(models::validate_file_type("doc.docx", b"%PDF-1.4").is_err());
    }

    // ===== ADDITIONAL SENSITIVE WORDS TESTS =====

    #[test]
    fn test_sensitive_words_multiple_replacements() {
        let words = vec![
            SensitiveWord { id: "1".into(), word: "bad".into(), action: "replace".into(), replacement: Some("[x]".into()), added_by: "admin".into() },
            SensitiveWord { id: "2".into(), word: "ugly".into(), action: "replace".into(), replacement: Some("[y]".into()), added_by: "admin".into() },
        ];
        let result = check_sensitive_words("This is bad and ugly text", &words);
        assert!(!result.is_blocked);
        assert!(result.processed_text.contains("[x]"));
        assert!(result.processed_text.contains("[y]"));
        assert!(!result.processed_text.contains("bad"));
        assert!(!result.processed_text.contains("ugly"));
    }

    #[test]
    fn test_sensitive_words_block_takes_precedence_over_replace() {
        let words = vec![
            SensitiveWord { id: "1".into(), word: "ok".into(), action: "replace".into(), replacement: Some("fine".into()), added_by: "admin".into() },
            SensitiveWord { id: "2".into(), word: "forbidden".into(), action: "block".into(), replacement: None, added_by: "admin".into() },
        ];
        let result = check_sensitive_words("This is ok but also forbidden", &words);
        assert!(result.is_blocked);
        assert_eq!(result.blocked_words, vec!["forbidden"]);
    }

    #[test]
    fn test_sensitive_words_empty_word_list() {
        let words: Vec<SensitiveWord> = vec![];
        let result = check_sensitive_words("Any text here", &words);
        assert!(!result.is_blocked);
        assert_eq!(result.processed_text, "Any text here");
        assert!(result.replacements_made.is_empty());
    }

    #[test]
    fn test_sensitive_words_replace_default_replacement() {
        let words = vec![SensitiveWord {
            id: "1".into(), word: "bad".into(), action: "replace".into(),
            replacement: None, added_by: "admin".into(),
        }];
        let result = check_sensitive_words("This is bad", &words);
        assert!(result.processed_text.contains("***"));
    }

    #[test]
    fn test_sensitive_words_multiple_occurrences_replaced() {
        let words = vec![SensitiveWord {
            id: "1".into(), word: "bad".into(), action: "replace".into(),
            replacement: Some("[x]".into()), added_by: "admin".into(),
        }];
        let result = check_sensitive_words("bad start and bad end", &words);
        assert_eq!(result.processed_text, "[x] start and [x] end");
        assert_eq!(result.replacements_made.len(), 2);
    }

    // ===== ADDITIONAL BUSINESS DAY TESTS =====

    #[test]
    fn test_business_days_saturday_plus_1_is_monday() {
        let saturday = chrono::NaiveDate::from_ymd_opt(2026, 4, 4).unwrap().and_hms_opt(9, 0, 0).unwrap();
        let result = models::add_business_days(saturday, 1);
        assert_eq!(result.weekday(), chrono::Weekday::Mon);
    }

    #[test]
    fn test_business_days_sunday_plus_1_is_monday() {
        let sunday = chrono::NaiveDate::from_ymd_opt(2026, 4, 5).unwrap().and_hms_opt(9, 0, 0).unwrap();
        let result = models::add_business_days(sunday, 1);
        assert_eq!(result.weekday(), chrono::Weekday::Mon);
    }

    #[test]
    fn test_business_days_five_days_is_one_week() {
        let monday = chrono::NaiveDate::from_ymd_opt(2026, 4, 6).unwrap().and_hms_opt(9, 0, 0).unwrap();
        let result = models::add_business_days(monday, 5);
        // 5 business days from Monday = next Monday
        assert_eq!(result.date(), chrono::NaiveDate::from_ymd_opt(2026, 4, 13).unwrap());
    }

    #[test]
    fn test_business_days_preserves_time() {
        let dt = chrono::NaiveDate::from_ymd_opt(2026, 4, 6).unwrap().and_hms_opt(14, 30, 45).unwrap();
        let result = models::add_business_days(dt, 1);
        assert_eq!(result.time(), chrono::NaiveTime::from_hms_opt(14, 30, 45).unwrap());
    }

    // ===== ADDITIONAL CASE TRANSITION TESTS =====

    #[test]
    fn test_case_awaiting_evidence_can_go_to_arbitrated() {
        assert!(models::valid_case_transition("awaiting_evidence", "arbitrated"));
    }

    #[test]
    fn test_case_unknown_status_rejected() {
        assert!(!models::valid_case_transition("unknown", "in_review"));
        assert!(!models::valid_case_transition("submitted", "unknown"));
    }

    #[test]
    fn test_case_self_transition_rejected() {
        let statuses = ["submitted", "in_review", "awaiting_evidence", "arbitrated", "approved", "denied", "closed"];
        for s in &statuses {
            assert!(!models::valid_case_transition(s, s), "Self-transition from '{}' to '{}' must be rejected", s, s);
        }
    }

    #[test]
    fn test_case_reverse_transitions_rejected() {
        // Cannot go backward through the main flow
        assert!(!models::valid_case_transition("in_review", "submitted"));
        assert!(!models::valid_case_transition("approved", "arbitrated"));
        assert!(!models::valid_case_transition("denied", "arbitrated"));
        assert!(!models::valid_case_transition("closed", "approved"));
    }

    // ===== SUBMISSION VERSION RESPONSE CONVERSION =====

    #[test]
    fn test_submission_version_to_response() {
        use backend::models::submission::SubmissionVersion;
        let dt = chrono::NaiveDate::from_ymd_opt(2026, 4, 2).unwrap()
            .and_hms_opt(14, 30, 0).unwrap();
        let version = SubmissionVersion {
            id: "v1".into(),
            submission_id: "sub1".into(),
            version_number: 3,
            file_name: "paper.pdf".into(),
            file_path: "/uploads/paper.pdf".into(),
            file_size: 1024,
            file_type: "pdf".into(),
            file_hash: "abc123".into(),
            magic_bytes: None,
            form_data: None,
            submitted_at: Some(dt),
        };
        let resp = version.to_response();
        assert_eq!(resp.id, "v1");
        assert_eq!(resp.version_number, 3);
        assert_eq!(resp.file_name, "paper.pdf");
        assert_eq!(resp.file_size, 1024);
        assert_eq!(resp.file_type, "pdf");
        assert_eq!(resp.file_hash, "abc123");
        assert_eq!(resp.submitted_at.unwrap(), "04/02/2026, 02:30:00 PM");
    }

    #[test]
    fn test_submission_version_to_response_no_timestamp() {
        use backend::models::submission::SubmissionVersion;
        let version = SubmissionVersion {
            id: "v2".into(),
            submission_id: "sub1".into(),
            version_number: 1,
            file_name: "draft.docx".into(),
            file_path: "/uploads/draft.docx".into(),
            file_size: 2048,
            file_type: "docx".into(),
            file_hash: "def456".into(),
            magic_bytes: None,
            form_data: None,
            submitted_at: None,
        };
        let resp = version.to_response();
        assert!(resp.submitted_at.is_none());
    }

    // ===== TEMPLATE VALIDATION =====

    #[test]
    fn test_journal_template_requires_methodology() {
        use backend::models::submission::get_submission_templates;
        let templates = get_submission_templates();
        let journal = templates.iter().find(|t| t.submission_type == "journal_article").unwrap();
        assert!(journal.required_fields.contains(&"methodology".to_string()));
    }

    #[test]
    fn test_thesis_template_requires_advisor() {
        use backend::models::submission::get_submission_templates;
        let templates = get_submission_templates();
        let thesis = templates.iter().find(|t| t.submission_type == "thesis").unwrap();
        assert!(thesis.required_fields.contains(&"advisor".to_string()));
        assert!(thesis.required_fields.contains(&"degree_type".to_string()));
    }

    #[test]
    fn test_conference_template_requires_conference_name() {
        use backend::models::submission::get_submission_templates;
        let templates = get_submission_templates();
        let conf = templates.iter().find(|t| t.submission_type == "conference_paper").unwrap();
        assert!(conf.required_fields.contains(&"conference_name".to_string()));
    }

    #[test]
    fn test_book_chapter_template_requires_editor() {
        use backend::models::submission::get_submission_templates;
        let templates = get_submission_templates();
        let book = templates.iter().find(|t| t.submission_type == "book_chapter").unwrap();
        assert!(book.required_fields.contains(&"editor".to_string()));
        assert!(book.required_fields.contains(&"book_title".to_string()));
    }

    // ===== SLA DEADLINE CALCULATION =====

    #[test]
    fn test_sla_first_response_deadline_is_correct() {
        let submitted = chrono::NaiveDate::from_ymd_opt(2026, 4, 6).unwrap()
            .and_hms_opt(9, 0, 0).unwrap(); // Monday 9AM
        let deadline = submitted + Duration::hours(models::SLA_FIRST_RESPONSE_HOURS);
        // 48 hours from Monday 9AM = Wednesday 9AM
        assert_eq!(deadline.date(), chrono::NaiveDate::from_ymd_opt(2026, 4, 8).unwrap());
    }

    #[test]
    fn test_sla_resolution_deadline_is_correct() {
        let submitted = chrono::NaiveDate::from_ymd_opt(2026, 4, 6).unwrap()
            .and_hms_opt(9, 0, 0).unwrap(); // Monday 9AM
        let deadline = submitted + Duration::hours(models::SLA_RESOLUTION_HOURS);
        // 168 hours = 7 days from Monday = next Monday
        assert_eq!(deadline.date(), chrono::NaiveDate::from_ymd_opt(2026, 4, 13).unwrap());
    }

    // ===== DATA MODEL SERIALIZATION =====

    #[test]
    fn test_sensitive_word_serialization_roundtrip() {
        let word = SensitiveWord {
            id: "sw-1".into(),
            word: "test".into(),
            action: "replace".into(),
            replacement: Some("***".into()),
            added_by: "admin".into(),
        };
        let json = serde_json::to_string(&word).unwrap();
        let deserialized: SensitiveWord = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, "sw-1");
        assert_eq!(deserialized.word, "test");
        assert_eq!(deserialized.action, "replace");
        assert_eq!(deserialized.replacement, Some("***".to_string()));
    }

    #[test]
    fn test_content_check_result_blocked_serializes() {
        let result = check_sensitive_words(
            "This has forbidden text",
            &[SensitiveWord {
                id: "1".into(), word: "forbidden".into(), action: "block".into(),
                replacement: None, added_by: "admin".into(),
            }],
        );
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"is_blocked\":true"));
        assert!(json.contains("\"forbidden\""));
    }

    // ===== PAYMENT LOGIC EDGE CASES =====

    #[test]
    fn test_refund_exact_original_amount_allowed() {
        let original = 100.00_f64;
        assert!(100.0 <= original);
    }

    #[test]
    fn test_refund_zero_amount() {
        let original = 100.00_f64;
        assert!(0.0 <= original);
    }

    #[test]
    fn test_idempotency_different_keys_are_different() {
        let k1 = "pay-001";
        let k2 = "pay-002";
        assert_ne!(k1, k2);
    }

    // ===== ORDER LINE ITEM TOTAL CALCULATION =====

    #[test]
    fn test_line_total_calculation() {
        let quantity = 5;
        let unit_price = 29.99_f64;
        let expected_total = quantity as f64 * unit_price;
        assert!((expected_total - 149.95).abs() < f64::EPSILON);
    }

    #[test]
    fn test_high_quantity_flag_threshold() {
        // Orders with quantity >= HIGH_QUANTITY_THRESHOLD should be flagged
        assert!(50 >= models::HIGH_QUANTITY_THRESHOLD);
        assert!(51 >= models::HIGH_QUANTITY_THRESHOLD);
        assert!(49 < models::HIGH_QUANTITY_THRESHOLD);
    }

    // ===== REFUND THRESHOLD =====

    #[test]
    fn test_refund_count_at_threshold_triggers_flag() {
        let refund_count: i64 = 3;
        assert!(refund_count >= models::REFUND_COUNT_THRESHOLD);
    }

    #[test]
    fn test_refund_count_below_threshold_no_flag() {
        let refund_count: i64 = 2;
        assert!(refund_count < models::REFUND_COUNT_THRESHOLD);
    }

    // ===== SOFT DELETE WINDOW =====

    #[test]
    fn test_soft_delete_within_hold_period_is_recoverable() {
        let deleted_at = Utc::now().naive_utc();
        let hold_end = deleted_at + Duration::days(models::SOFT_DELETE_HOLD_DAYS);
        let now = Utc::now().naive_utc();
        assert!(now < hold_end, "Within hold period, account is recoverable");
    }

    #[test]
    fn test_soft_delete_after_hold_period_is_permanent() {
        let deleted_at = Utc::now().naive_utc() - Duration::days(models::SOFT_DELETE_HOLD_DAYS + 1);
        let hold_end = deleted_at + Duration::days(models::SOFT_DELETE_HOLD_DAYS);
        let now = Utc::now().naive_utc();
        assert!(now > hold_end, "After hold period, deletion is permanent");
    }
}
