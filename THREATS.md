\# TrustVault Threat Model



\## 1. Purpose and Scope



TrustVault is a Flask application for private document storage, document sharing, and audit logging.



This threat model identifies likely attacks against authentication, document confidentiality, authorization, file uploads, permission management, audit records, and stored files.



The mitigations described as implemented are based on the current application code inspected during development. Proposed improvements are identified separately.



\## 2. Assets to Protect



1\. Uploaded document contents.

2\. Document metadata, including title, category, and original filename.

3\. User accounts and password hashes.

4\. Document ownership and sharing permissions.

5\. Audit events recording successful and refused operations.

6\. Session credentials and authenticated user identity.

7\. Private files stored on the server.

8\. Database integrity and application availability.



\## 3. Roles and Trust Boundaries



\### Anonymous user



Can access the home page, health endpoint, registration page, and login page. Must not access protected document operations.



\### Viewer



Newly registered accounts receive the `viewer` role. A viewer should only access documents they own or documents explicitly shared with them.



\### Document owner



Can download, share, revoke access, edit metadata, and delete their own documents.



\### User with read permission



Can download the shared document. This permission does not authorize sharing, revocation, metadata editing, or deletion.



\### User with edit permission



The authorization helper recognizes this permission for read and edit access. However, the current metadata-edit route checks ownership directly, so shared users with edit permission cannot edit metadata through that route.



\### Administrator



Can access the administrator page through the `admin` role check. The admin role alone does not automatically grant document access through the document routes.



\## 4. Threats, Mitigations, and Residual Risks



\### T1. Unauthorized document download



\*\*Attack:\*\* A user guesses or obtains another document's numeric ID and requests its download URL.



\*\*Potential impact:\*\* Confidential documents are disclosed.



\*\*Existing mitigations:\*\*

\- Download requires authentication.

\- The route checks document existence.

\- `can\_read\_document()` allows the owner or a user with `read` or `edit` permission.

\- Unauthorized attempts are explicitly recorded as denied before the route returns HTTP 403.



\*\*Residual risk:\*\* All routes that expose document content must enforce equivalent authorization. A future route that reads the storage file directly without checking permission could bypass the download control.



\*\*Verification:\*\* `test\_user\_cannot\_download\_private\_document`, `test\_shared\_user\_can\_download\_document`, and `test\_revoked\_user\_cannot\_download\_document`.



\### T2. Unauthorized permission changes



\*\*Attack:\*\* A viewer or recipient submits a forged share or revoke request for a document they do not own.



\*\*Potential impact:\*\* Unauthorized users gain access or legitimate access is removed.



\*\*Existing mitigations:\*\*

\- Share and revoke routes require authentication.

\- Both routes check that the current user owns the document.

\- Explicitly handled unauthorized attempts are recorded.

\- Sharing accepts only `read` and `edit` permission values.

\- The recipient must be an existing active account.



\*\*Residual risk:\*\* These controls must remain in place if new sharing interfaces or API endpoints are added. Review CSRF protection for every state-changing browser request and confirm it is enabled in the deployed configuration.



\*\*Verification:\*\* `test\_owner\_can\_share\_document` and `test\_owner\_can\_revoke\_document\_access`.



\### T3. Access after permission revocation



\*\*Attack:\*\* A previously authorized recipient attempts to download a document after the owner revokes access.



\*\*Potential impact:\*\* A former recipient continues to access a private document.



\*\*Existing mitigations:\*\*

\- Revocation deletes the corresponding permission record.

\- Download authorization checks the current permission records.

\- The revocation and audit event are committed in the database transaction.



\*\*Residual risk:\*\* Revocation prevents future authorized requests but cannot retract a copy that the recipient downloaded before revocation.



\*\*Verification:\*\* `test\_revoked\_user\_cannot\_download\_document`.



\### T4. Unauthorized metadata editing or deletion



\*\*Attack:\*\* A non-owner submits a forged edit or delete request with a known document ID.



\*\*Potential impact:\*\* Document metadata is changed or a document is destroyed.



\*\*Existing mitigations:\*\*

\- Both routes require authentication.

\- Both routes check ownership.

\- Explicitly handled unauthorized attempts are recorded.

\- Successful metadata updates and deletions are audited.



\*\*Residual risk:\*\* The application does not provide recovery of deleted documents in the inspected deletion implementation. A file-cleanup failure after database commit can leave an orphaned private file.



**Verification:** `test_viewer_cannot_edit_another_users_document` verifies that an unauthorized edit returns HTTP 403, preserves the original title and category, and records a denied audit event. `test_viewer_cannot_delete_another_users_document` verifies that an unauthorized delete returns HTTP 403, preserves the document record, and records a denied audit event. Both tests passed in the development test run.



\### T5. Malicious or misleading file uploads



\*\*Attack:\*\* An attacker uploads a file with a misleading extension, an empty file, an oversized file, or content inconsistent with the extension.



\*\*Potential impact:\*\* Invalid content is stored, storage resources are exhausted, or a downstream consumer mishandles a file.



\*\*Existing mitigations:\*\*

\- Filename sanitization is applied.

\- File extensions are checked against an allowlist.

\- Empty uploads are rejected.

\- Upload size is limited to 10 MB.

\- Basic file signatures are checked for supported formats.

\- Incomplete uploads are cleaned up where possible.

\- Upload outcomes are audited in explicitly handled paths.



\*\*Residual risk:\*\* Signature checks are not malware scanning. Text-file validation is basic, and file-format validation cannot guarantee that a file is safe to open. A cleanup failure may leave an unwanted file on disk.



\*\*Verification:\*\* `test\_upload\_rejects\_unsupported\_file\_type`, `test\_upload\_accepts\_text\_file`, `test\_upload\_rejects\_invalid\_text\_signature`, and `test\_upload\_rejects\_empty\_file`.



\### T6. Password compromise or account impersonation



\*\*Attack:\*\* An attacker guesses passwords, uses stolen credentials, or attempts to log in to an inactive account.



\*\*Potential impact:\*\* The attacker gains access to documents permitted for the compromised account.



\*\*Existing mitigations:\*\*

\- Passwords are stored as hashes rather than plaintext.

\- Login verifies the password hash.

\- Inactive accounts are rejected.

\- A successful login creates a fresh authenticated session.



\*\*Residual risk:\*\* The inspected code does not establish that rate limiting, multi-factor authentication, breached-password checks, or account lockout are implemented. A compromised account can still be abused within its permissions.



\*\*Recommended improvements:\*\* Add login rate limiting, strong password policy, secure production cookie settings, and optional multi-factor authentication.



\### T7. Session misuse or cross-site request forgery



\*\*Attack:\*\* An attacker attempts to reuse a stolen session or induce a logged-in user to submit an unwanted state-changing request.



\*\*Potential impact:\*\* The attacker performs actions using the victim's permissions.



\*\*Existing mitigations:\*\* Protected routes use Flask-Login authentication checks.



\*\*Residual risk:\*\* Authentication alone does not prove that session-cookie security settings or CSRF protection are correctly configured. The inspected route excerpts do not establish the deployment settings for these controls.



\*\*Recommended improvements:\*\* Verify secure, HTTP-only, and appropriate SameSite cookie settings under HTTPS. Ensure CSRF tokens protect all state-changing form requests, including upload, share, revoke, edit, and delete.



\### T8. Audit event loss or tampering



\*\*Attack:\*\* A database error prevents an audit event from being saved, or a person with sufficient database access alters or removes audit records.



\*\*Potential impact:\*\* Security incidents become difficult to investigate, and the audit trail becomes incomplete or unreliable.



\*\*Existing mitigations:\*\*

\- Audit events record actions and outcomes.

\- Selected security denials are recorded.

\- Some successful operations commit their audit record in the same transaction as the corresponding database change.

\- Deletion events do not reference the document row that is being deleted.

\- Automated tests check audit persistence, invalid outcomes, and retention after actor deletion.



\*\*Residual risk:\*\*

\- The general audit helper catches persistence errors and logs them to the application logger; it does not guarantee that the database audit event was saved.

\- A database administrator or attacker with database write access may alter audit records.

\- The current design is not independently tamper-proof or an immutable external audit service.



\*\*Recommended improvements:\*\* Restrict database write access, export security logs to a separately controlled system, monitor audit-write failures, and consider append-only or tamper-evident storage.



\*\*Verification:\*\* `test\_audit\_event\_is\_persisted`, `test\_audit\_log\_rejects\_invalid\_outcome`, and `test\_audit\_log\_survives\_user\_deletion`.



\### T9. Unauthorized role access



\*\*Attack:\*\* A non-admin user directly requests `/admin`.



\*\*Potential impact:\*\* Administrative functionality or data is exposed.



\*\*Existing mitigations:\*\*

\- The admin route uses the role-protection decorator.

\- The decorator checks the current user's role and returns HTTP 403 on denial.

\- The decorator attempts to record a `role\_access\_denied` event.



\*\*Residual risk:\*\* The admin page's underlying functionality and data exposure should be tested independently as it grows.



\*\*Verification:\*\* `test\_viewer\_cannot\_access\_admin\_page`.



\### T10. Database inconsistency or orphaned storage files



\*\*Attack or failure:\*\* A database operation fails partway through an upload, permission change, or deletion, or filesystem cleanup fails.



\*\*Potential impact:\*\* Inconsistent metadata, stale permissions, or files that are no longer represented by database records.



\*\*Existing mitigations:\*\*

\- Upload database changes and the success audit event use a shared transaction.

\- Permission revocation writes the audit event and removes the permission in one transaction.

\- Database failures trigger rollback in the inspected upload, edit, revoke, and delete handlers.

\- SQLite foreign-key enforcement is enabled through a SQLAlchemy engine connection event.



\*\*Residual risk:\*\* Database transactions cannot make filesystem changes atomic with database commits. Deletion currently removes the file after committing the database transaction.



\*\*Recommended improvements:\*\* Add orphan-file reconciliation, controlled cleanup retries, and tests for simulated filesystem failures.



\## 5. Security Tests and Evidence



The current automated suite contains tests for:



\- Authentication required for the dashboard.

\- Viewer denial from the administrator page.

\- Denial of unauthorized private-document downloads.

\- Authorized shared-document downloads.

\- Immediate denial after permission revocation.

\- Owner-authorized sharing and revocation.

\- Upload extension, content-signature, and empty-file validation.

\- Audit event persistence, valid outcomes, and retention after user deletion.



Unauthorized metadata editing and unauthorized deletion are covered by `test_viewer_cannot_edit_another_users_document` and `test_viewer_cannot_delete_another_users_document`. Both tests passed. CSRF behavior, login rate limiting, audit database failure, and file-cleanup failure still require dedicated tests before those cases can be claimed as verified.



Run the test suite with:



&#x20;   python -m pytest -v



Record the actual output when documenting test results. Do not report a test as passing unless the command confirms it.



\## 6. Accepted Risks



For the current development version, the following limitations are acknowledged rather than treated as solved:



1\. Basic file-signature validation does not replace malware scanning.

2\. A recipient may retain a copy downloaded before permission revocation.

3\. Audit records in the application database are not independently tamper-proof.

4\. Filesystem cleanup may fail after a database deletion commits.

5\. The inspected code does not establish production-grade rate limiting or multi-factor authentication.

6\. Date-based document search is not currently implemented.

7\. The metadata-edit route currently restricts edits to owners, including when a recipient has `edit` permission.



These risks should be reassessed before production deployment.



\## 7. Review Checklist



\- \[ ] Every document-content route checks authentication and document-level authorization.

\- \[ ] Sharing and revocation are owner-only.

\- \[ ] Revoked recipients cannot make new authorized downloads.

\- \[ ] Upload validation rejects invalid and oversized files.

\- \[ ] Security-relevant successes and failures are audited.

\- \[ ] Audit-write failures are observable.

\- \[ ] CSRF and production session settings are verified.

- [x] Unauthorized edit and delete tests are added and passing.

\- \[ ] Filesystem cleanup and orphan-file handling are tested.

\- \[ ] Documentation matches the actual code and automated test results.

