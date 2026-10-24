# TrustVault Threat Model

## 1. Purpose and Scope

TrustVault is a Flask application for private document storage, document sharing, and audit logging.

This threat model identifies likely attacks against authentication, document confidentiality, authorization, file uploads, permission management, audit records, and stored files.

The mitigations described as implemented are based on the application code and development tests inspected during development. Proposed improvements and unresolved risks are identified separately.

## 2. Assets to Protect

1. Uploaded document contents.
2. Document metadata, including title, category, and original filename.
3. User accounts and password hashes.
4. Document ownership and sharing permissions.
5. Audit events recording successful and refused operations.
6. Session credentials and authenticated user identity.
7. Private files stored on the server.
8. Database integrity and application availability.

## 3. Roles and Trust Boundaries

### Anonymous user

Can access the home page, health endpoint, registration page, and login page. Must not access protected document operations.

### Viewer

During registration, users can choose either the `viewer` role or the document-owner role. Administrator access is not offered as a public registration choice. A viewer should only access documents they own or documents explicitly shared with them.

### Document owner

Can download, share, revoke access, edit metadata, and delete their own documents.

### User with read permission

Can download the shared document. This permission does not authorize sharing, revocation, metadata editing, or deletion.

### User with edit permission

The authorization helper recognizes this permission for read and edit access. However, the current metadata-edit route checks ownership directly, so shared users with edit permission cannot edit metadata through that route.

### Administrator

Can access the administrator page through the `admin` role check. The admin role alone does not automatically grant document access through the document routes.

## 4. Threats, Mitigations, and Residual Risks

### T1. Unauthorized document download

**Attack:** A user guesses or obtains another document's numeric ID and requests its download URL.

**Potential impact:** Confidential documents are disclosed.

**Existing mitigations:**

- Download requires authentication.
- The route checks document existence.
- `can_read_document()` allows the owner or a user with `read` or `edit` permission.
- Unauthorized attempts are explicitly recorded as denied before the route returns HTTP 403.

**Residual risk:** All routes that expose document content must enforce equivalent authorization. A future route that reads a storage file directly without checking permission could bypass the download control.

**Verification:** `test_user_cannot_download_private_document`, `test_shared_user_can_download_document`, and `test_revoked_user_cannot_download_document`.

### T2. Unauthorized permission changes

**Attack:** A viewer or recipient submits a forged share or revoke request for a document they do not own.

**Potential impact:** Unauthorized users gain access or legitimate access is removed.

**Existing mitigations:**

- Share and revoke routes require authentication.
- Both routes check that the current user owns the document.
- Explicitly handled unauthorized attempts are recorded.
- Sharing accepts only `read` and `edit` permission values.
- The recipient must be an existing active account.

**Residual risk:** These controls must remain in place if new sharing interfaces or API endpoints are added. CSRF protection must be verified for every state-changing browser request and in the deployed configuration.

**Verification:** `test_owner_can_share_document` and `test_owner_can_revoke_document_access`.

### T3. Access after permission revocation

**Attack:** A previously authorized recipient attempts to download a document after the owner revokes access.

**Potential impact:** A former recipient continues to access a private document.

**Existing mitigations:**

- Revocation deletes the corresponding permission record.
- Download authorization checks current permission records.
- The revocation and audit event are committed in the database transaction.

**Residual risk:** Revocation prevents future authorized requests but cannot retract a copy that the recipient downloaded before revocation.

**Verification:** `test_revoked_user_cannot_download_document`.

### T4. Unauthorized metadata editing or deletion

**Attack:** A non-owner submits a forged edit or delete request with a known document ID.

**Potential impact:** Document metadata is changed or a document is destroyed.

**Existing mitigations:**

- Both routes require authentication.
- Both routes check ownership.
- Explicitly handled unauthorized attempts are recorded.
- Successful metadata updates and deletions are audited.

**Residual risk:** The application does not provide recovery of deleted documents in the inspected deletion implementation. A file-cleanup failure after database commit can leave an orphaned private file.

**Verification:** `test_viewer_cannot_edit_another_users_document` verifies that an unauthorized edit returns HTTP 403, preserves the original title and category, and records a denied audit event. `test_viewer_cannot_delete_another_users_document` verifies that an unauthorized delete returns HTTP 403, preserves the document record, and records a denied audit event. Both tests passed in the recorded development test run.

### T5. Malicious or misleading file uploads

**Attack:** An attacker uploads a file with a misleading extension, an empty file, an oversized file, or content inconsistent with the extension.

**Potential impact:** Invalid content is stored, storage resources are exhausted, or a downstream consumer mishandles a file.

**Existing mitigations:**

- Filename sanitization is applied.
- File extensions are checked against an allowlist.
- Empty uploads are rejected.
- Upload size is limited to 10 MB.
- Basic file signatures are checked for supported formats.
- Incomplete uploads are cleaned up where possible.
- Upload outcomes are audited in explicitly handled paths.
- Requests rejected by the oversized-request error handler generate a failure audit event.

**Residual risk:** Signature checks are not malware scanning. Text-file validation is basic, and file-format validation cannot guarantee that a file is safe to open. A cleanup failure may leave an unwanted file on disk.

**Verification:** `test_upload_rejects_unsupported_file_type`, `test_upload_accepts_text_file`, `test_upload_rejects_invalid_text_signature`, `test_upload_rejects_empty_file`, and `test_upload_rejects_file_over_size_limit`.

The oversized-upload test verifies rejection, absence of a created document record, and the presence of a failure audit event.

### T6. Password compromise or account impersonation

**Attack:** An attacker guesses passwords, uses stolen credentials, or attempts to log in to an inactive account.

**Potential impact:** The attacker gains access to documents permitted for the compromised account.

**Existing mitigations:**

- Passwords are stored as hashes rather than plaintext.
- Login verifies the password hash.
- Inactive accounts are rejected.
- A successful login creates a fresh authenticated session.
- Login rate limiting is configured and has a dedicated regression test.

**Residual risk:** Rate limiting reduces repeated login attempts but does not prevent every credential attack. Multi-factor authentication and breached-password checks are not established as implemented. A compromised account can still be abused within its permissions.

**Recommended improvements:** Review the production rate-limit configuration, maintain a strong password policy, verify secure production cookie settings, and consider optional multi-factor authentication.

### T7. Session misuse or cross-site request forgery

**Attack:** An attacker attempts to reuse a stolen session or induce a logged-in user to submit an unwanted state-changing request.

**Potential impact:** The attacker performs actions using the victim's permissions.

**Existing mitigations:**

- Protected routes use Flask-Login authentication checks.
- CSRF protection has a dedicated regression test for rejecting a login POST without a CSRF token.

**Residual risk:** Authentication alone does not prove that session-cookie security settings or CSRF protection are correctly configured in production. The login CSRF test does not independently verify every state-changing route or invalid and expired tokens.

**Recommended improvements:**

- Verify secure, HTTP-only, and appropriate SameSite cookie settings under HTTPS.
- Ensure CSRF tokens protect all state-changing form requests, including upload, share, revoke, edit, and delete.
- Test valid, missing, invalid, and expired CSRF tokens where applicable.
- Verify session behavior in the deployed configuration.

### T8. Audit event loss or tampering

**Attack:** A database error prevents an audit event from being saved, or a person with sufficient database access alters or removes audit records.

**Potential impact:** Security incidents become difficult to investigate, and the audit trail becomes incomplete or unreliable.

**Existing mitigations:**

- Audit events record actions and outcomes.
- Selected security denials are recorded.
- Some successful operations commit their audit record in the same transaction as the corresponding database change.
- Deletion events do not reference the document row that is being deleted.
- Automated tests check audit persistence, valid outcomes, and retention after actor deletion.
- A database commit-failure test checks rollback attempts, error logging, and exception handling.

**Residual risk:**

- The general audit helper catches persistence errors and logs them to the application logger; it does not guarantee that the database audit event was saved.
- A database administrator or attacker with database write access may alter audit records.
- The current design is not independently tamper-proof or an immutable external audit service.

**Recommended improvements:** Restrict database write access, export security logs to a separately controlled system, monitor audit-write failures, and consider append-only or tamper-evident storage.

**Verification:** `test_audit_event_is_persisted`, `test_audit_log_rejects_invalid_outcome`, `test_audit_log_survives_user_deletion`, and `test_record_audit_handles_database_commit_failure`.

The failure test simulates a commit exception and verifies that the helper attempts rollback, logs the failure, and does not propagate the exception. It does not establish that an audit event is persisted when the database is unavailable.

### T9. Unauthorized role access

**Attack:** A non-admin user directly requests `/admin`.

**Potential impact:** Administrative functionality or data is exposed.

**Existing mitigations:**

- The admin route uses the role-protection decorator.
- The decorator checks the current user's role and returns HTTP 403 on denial.
- The decorator attempts to record a `role_access_denied` event. The passing access-denial test verifies the denial behavior; it does not independently establish that this specific audit event was persisted.

**Residual risk:** The admin page's underlying functionality and data exposure should be tested independently as it grows.

**Verification:** `test_viewer_cannot_access_admin_page`.

### T10. Database inconsistency or orphaned storage files

**Attack or failure:** A database operation fails partway through an upload, permission change, or deletion, or filesystem cleanup fails.

**Potential impact:** Inconsistent metadata, stale permissions, or files that are no longer represented by database records.

**Existing mitigations:**

- Upload database changes and the success audit event use a shared transaction.
- Permission revocation writes the audit event and removes the permission in one transaction.
- Database failures trigger rollback in the inspected upload, edit, revoke, and delete handlers.
- SQLite foreign-key enforcement is enabled through a SQLAlchemy engine connection event.

**Residual risk:** Database transactions cannot make filesystem changes atomic with database commits. Deletion currently removes the file after committing the database transaction.

**Recommended improvements:** Add orphan-file reconciliation, controlled cleanup retries, and tests for simulated filesystem failures.

## 5. Security Tests and Evidence

The latest verified full-suite run passed **21 tests** using `python -m pytest .\test_app.py -v` on 2026-10-24. Rerun the suite after subsequent changes.

The automated tests cover:

- Authentication required for the dashboard.
- Viewer denial from the administrator page.
- Denial of unauthorized private-document downloads.
- Authorized shared-document downloads.
- Denial of downloads after permission revocation.
- Owner-authorized sharing and revocation.
- Upload extension, content-signature, empty-file, and oversized-file validation.
- Audit event persistence, valid outcomes, and retention after user deletion.
- Unauthorized metadata editing and deletion.
- CSRF rejection for a login POST without a token.
- Login rate limiting.
- Audit-helper behavior when a database commit fails.

**Unauthorized metadata editing and deletion:** `test_viewer_cannot_edit_another_users_document` and `test_viewer_cannot_delete_another_users_document` verify HTTP 403, preservation of the document data or record, and a denied audit event.

**Oversized uploads:** `test_upload_rejects_file_over_size_limit` verifies that an oversized request is rejected, no document record is created, and a failure audit event is recorded.

**CSRF protection:** `test_csrf_rejects_post_without_token` temporarily enables `WTF_CSRF_ENABLED` and verifies that a login POST without a CSRF token returns HTTP 400. This test does not independently verify every state-changing route or test invalid and expired tokens.

**Login rate limiting:** A dedicated regression test checks the configured login-attempt limit. Production deployment settings should still be reviewed.

**Audit database commit failure:** `test_record_audit_handles_database_commit_failure` checks exception handling, rollback attempts, and error logging. Reliable audit persistence during database failure remains unresolved.

**Remaining test gap:** File-cleanup failure and orphan-file handling still require dedicated tests.

Run the test suite with:

```powershell
python -m pytest -v
```

Record the actual output when documenting test results. Do not report a test as passing unless the command confirms it.

## 6. Accepted Risks

For the current development version, the following limitations are acknowledged rather than treated as solved:

1. Basic file-signature validation does not replace malware scanning.
2. A recipient may retain a copy downloaded before permission revocation.
3. Audit records in the application database are not independently tamper-proof.
4. Filesystem cleanup may fail after a database deletion commits.
5. Login rate limiting is implemented, but production configuration and additional protections such as multi-factor authentication remain review items.
6. Date-based document search is not currently implemented.
7. The metadata-edit route currently restricts edits to owners, including when a recipient has `edit` permission.
8. Audit events may not be persisted if the database is unavailable or an audit transaction fails.

These risks should be reassessed before production deployment.

## 7. Review Checklist

- [ ] Every document-content route checks authentication and document-level authorization.
- [ ] Sharing and revocation are owner-only.
- [ ] Revoked recipients cannot make new authorized downloads.
- [x] Upload validation rejects invalid and oversized files, according to the recorded test results.
- [ ] Security-relevant successes and failures are audited comprehensively.
- [ ] Audit-write failures are observable and handled appropriately.
- [ ] CSRF and production session settings are verified across applicable routes.
- [x] Login rate limiting has a dedicated regression test.
- [x] Unauthorized edit and delete tests are added and passing in the recorded development test run.
- [ ] Filesystem cleanup and orphan-file handling are tested.
- [ ] Documentation matches the actual code and latest test results.
