# Fresh Issue Recheck 
Generated: 2026-04-10T09:04:54Z UTC
Boundary: Static-only (no runtime/tests/docker).


## Fixed/Not Fixed Status for Reported Issues

1) Startup/docs structure and endpoint-method mismatch concerns
- Status: Fixed
- Fixed part: previously cited route-method mismatches are now aligned.
- root README references to `repo/docs/api-spec.md` path.
- Evidence:
  - `docs/api-spec.md:73`, `repo/backend/src/routes/submissions.rs:720`
  - `docs/api-spec.md:108`, `repo/backend/src/routes/reviews.rs:63`
  - `docs/api-spec.md:157`, `repo/backend/src/routes/content.rs:172`
  - `README.md:48-49`
  - `test -f repo/docs/api-spec.md => REPO_DOCS_SPEC:1`

2) Frontend hardcoded localhost blocks LAN scenario
- Status: Fixed
- Evidence: `repo/frontend/src/services/api.rs:5-17` (host/protocol derived from browser location, localhost fallback)

3) Root API spec incorrect endpoints/methods vs implementation
- Status: Fixed for the previously cited endpoints
- Evidence:
  - `docs/api-spec.md:73` vs `repo/backend/src/routes/submissions.rs:720`
  - `docs/api-spec.md:108` vs `repo/backend/src/routes/reviews.rs:63`
  - `docs/api-spec.md:157` vs `repo/backend/src/routes/content.rs:172`

4) RBAC seed grants `users.manage` to academic staff
- Status: Fixed
- Evidence:
  - Academic staff permissions do not include `perm-users-manage`: `repo/backend/src/migrations/002_seed.sql:55-65`
  - Deactivate endpoint enforces admin role + `users.manage`: `repo/backend/src/routes/users.rs:124-129`

5) Security-critical flow coverage gaps (logout/templates/reconciliation)
- Status: Fixed for cited missing flows
- Evidence:
  - Logout invalidation: `repo/API_tests/src/lib.rs:1176-1199`
  - Templates endpoint: `repo/API_tests/src/lib.rs:1203-1232`
  - Reconciliation behavior/authz: `repo/API_tests/src/lib.rs:1490-1652`
  - Session timeout constant check: `repo/unit_tests/src/lib.rs:82-84`

6) Duplicate API specs (`docs/` vs `repo/docs/`) drift risk
- Status: Fixed 
- Evidence:
  - `test -f docs/api-spec.md => DOCS_SPEC:0`
  - `test -f repo/docs/api-spec.md => REPO_DOCS_SPEC:1`

## Current Status
- 6/6 Fixed
