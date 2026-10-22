\# TrustVault API Documentation



\## 1. Overview



TrustVault is a Flask-based application for authenticated document storage, controlled sharing, and audit logging.



Most document operations use HTML forms and return redirects rather than JSON responses.



\## 2. Authentication and Authorization



\- Unauthenticated users can access the home page, health check, registration, and login pages.

\- Authenticated users can access the dashboard and document operations.

\- New accounts receive the `viewer` role by default.

\- Only users with the `admin` role can access the admin page.

\- Document owners can download, share, revoke access, edit metadata, and delete their own documents.

\- Users granted `read` permission can download a document.

\- Users granted `edit` permission qualify for read and edit access in the authorization helper. However, the current metadata-edit route checks ownership directly, so only the owner can edit metadata through that route.

\- Administrator status alone does not grant document access.



\## 3. Endpoints



\### `GET /`



\*\*Access:\*\* Public



Displays the home page.



\*\*Response:\*\* HTML page.



\### `GET /health`



\*\*Access:\*\* Public



Returns the application health status.



\*\*Response:\*\*



&#x20;   {

&#x20;     "status": "ok",

&#x20;     "application": "TrustVault"

&#x20;   }



\### `GET /register`



\*\*Access:\*\* Public; authenticated users are redirected to the dashboard.



Displays the registration form.



\### `POST /register`



\*\*Access:\*\* Public; authenticated users are redirected to the dashboard.



Creates a user account after form validation.



\*\*Form fields:\*\* Name, email, and password, as defined by `RegistrationForm`.



\*\*Security behavior:\*\*

\- Email addresses are stripped of surrounding whitespace and converted to lowercase.

\- Passwords are stored as password hashes.

\- New accounts receive the `viewer` role.

\- Duplicate-email database errors are handled.



\*\*Response:\*\* Redirect to login after successful registration; otherwise, the registration form is rendered again.



\### `GET /login`



\*\*Access:\*\* Public; authenticated users are redirected to the dashboard.



Displays the login form.



\### `POST /login`



\*\*Access:\*\* Public; authenticated users are redirected to the dashboard.



Authenticates an active account using its email address and password.



\*\*Form fields:\*\* Email and password, as defined by `LoginForm`.



\*\*Security behavior:\*\*

\- Email addresses are normalized to lowercase.

\- Inactive accounts are rejected.

\- Passwords are checked against stored hashes.

\- Successful login creates a fresh authenticated session.



\*\*Response:\*\* Redirect to the dashboard after successful login; otherwise, the login form is rendered again.



\### `POST /logout`



\*\*Access:\*\* Authenticated users.



Logs out the current user.



\*\*Response:\*\* Redirect to the login page.



\### `GET /dashboard`



\*\*Access:\*\* Authenticated users.



Displays documents owned by the current user and documents shared with that user.



\*\*Query parameters:\*\*



| Parameter | Required | Description |

|---|---|---|

| `q` | No | Searches document title, original filename, category, and owner name. |



Documents are ordered by creation date, newest first.



\*\*Limitations:\*\* The current implementation does not provide a date-search parameter.



\### `GET /admin`



\*\*Access:\*\* Users with the `admin` role only.



Displays the administrator page.



\*\*Authorization failure:\*\* HTTP 403 for users without the required role. The role-protection decorator attempts to record a `role\_access\_denied` audit event.



\### `POST /documents/upload`



\*\*Access:\*\* Authenticated users.



Uploads a document owned by the current user.



\*\*Multipart form field:\*\*



| Field | Required | Description |

|---|---|---|

| `file` | Yes | The document file to upload. |



\*\*Validation:\*\*

\- The filename must be present and sanitized.

\- The extension must be in the application's configured allowlist.

\- Empty files are rejected.

\- Files exceeding the configured 10 MB limit are rejected.

\- File signatures are checked for supported formats.

\- TXT validation rejects NUL bytes in the initial sample.

\- DOCX validation checks for expected Office ZIP contents.



\*\*Storage:\*\* The application uses a generated UUID-based storage key rather than the original filename as the storage path.



\*\*Audit behavior:\*\* Upload failures are recorded where explicitly handled. The successful upload and its audit event are committed in one database transaction.



\*\*Response:\*\* Redirect to the dashboard with a status message.



\### `GET /documents/<document\_id>/download`



\*\*Access:\*\* Authenticated document owners and users with `read` or `edit` permission.



Downloads a document as an attachment.



\*\*Authorization behavior:\*\*

\- Returns HTTP 404 if the document does not exist.

\- Returns HTTP 403 if the user lacks read permission.

\- Returns HTTP 404 if the stored file is missing.

\- Records successful downloads and explicitly handled denied or missing-file events.



\*\*Response:\*\* File attachment using the original filename.



\### `POST /documents/<document\_id>/share`



\*\*Access:\*\* Authenticated document owner only.



Grants or updates a named user's permission.



\*\*Form fields:\*\*



| Field | Required | Description |

|---|---|---|

| `email` | Yes | Email address of an existing active recipient account. |

| `permission\_type` | Yes | `read` or `edit`. |



\*\*Validation:\*\*

\- Invalid permission types return HTTP 400.

\- Invalid or overlong email input returns HTTP 400.

\- The recipient must have an active account.

\- The owner cannot share the document with themselves.



\*\*Audit behavior:\*\* Successful new grants use `permission\_grant`; changes to an existing permission use `permission\_update`. Unauthorized sharing attempts are recorded where the route handles them.



\*\*Response:\*\* Redirect to the dashboard.



\### `POST /documents/<document\_id>/revoke/<user\_id>`



\*\*Access:\*\* Authenticated document owner only.



Revokes the specified user's permission for the document.



\*\*Path parameters:\*\*

\- `document\_id`: Document identifier.

\- `user\_id`: Recipient user identifier.



\*\*Audit behavior:\*\* Successful revocation and explicitly handled unauthorized attempts are recorded.



\*\*Response:\*\* Redirect to the dashboard. If the document or permission does not exist, the route follows its implemented not-found or status-message behavior.



\### `POST /documents/<document\_id>/edit`



\*\*Access:\*\* Authenticated document owner only.



Updates document metadata.



\*\*Form fields:\*\*



| Field | Required | Description |

|---|---|---|

| `title` | Yes | Non-empty title, maximum 200 characters. |

| `category` | Yes | Non-empty category, maximum 100 characters. |



\*\*Audit behavior:\*\* Successful edits and explicitly handled unauthorized attempts are recorded.



\*\*Response:\*\* Redirect to the dashboard.



\### `POST /documents/<document\_id>/delete`



\*\*Access:\*\* Authenticated document owner only.



Deletes the document record and associated permission records.



\*\*Audit behavior:\*\* A successful deletion event is written without a document foreign key, preserving the audit event after the document record is removed.



\*\*Storage behavior:\*\* The private file is removed after the database transaction commits. If file removal fails, the database record may already be deleted while the stored file remains and requires cleanup.



\*\*Response:\*\* Redirect to the dashboard.



\## 4. Access-Control Summary



| Operation | Owner | User with `read` permission | User with `edit` permission | Admin role alone |

|---|---|---|---|---|

| Download | Allowed | Allowed | Allowed | Not automatically allowed |

| Share | Allowed | Denied | Denied | Not automatically allowed |

| Revoke | Allowed | Denied | Denied | Not automatically allowed |

| Edit metadata through current route | Allowed | Denied | Denied | Not automatically allowed |

| Delete | Allowed | Denied | Denied | Not automatically allowed |

| Access `/admin` | Depends on role | Depends on role | Depends on role | Allowed |



\## 5. HTTP Status Codes



The application explicitly uses these status codes in the inspected routes:



\- `200 OK`: Normal page or health-check response.

\- `400 Bad Request`: Invalid sharing permission type or email input.

\- `403 Forbidden`: Authenticated user lacks required role or document authorization.

\- `404 Not Found`: Document does not exist or the stored download file is missing.

\- `413 Request Entity Too Large`: Used by the configured upload-size error handler when the request exceeds the request limit.



Other failures may be handled by Flask, form validation, or redirect-based user messages.



\## 6. Audit Logging



The application records events for document uploads, downloads, metadata edits, deletions, permission grants, permission updates, permission revocations, and selected denied operations.



Audit entries contain fields such as actor, document reference, action, outcome, and details. Some operations write their audit event in the same transaction as the database change.



\*\*Important limitation:\*\* The audit helper catches database exceptions and logs them to the application logger. Therefore, the existence of the helper does not guarantee that every audit event is successfully persisted. The current implementation also does not, by itself, establish tamper-proof audit storage.



\## 7. Scope and Limitations



\- The inspected routes primarily use HTML forms and redirects, not a JSON REST API.

\- Search currently covers title, original filename, category, and owner name, but not date.

\- The metadata-edit route does not currently allow users with `edit` permission to edit shared documents.

\- A deletion file-cleanup failure can leave a private file behind after its database record has been removed.

\- File-signature checks are basic validation, not antivirus or malware scanning.

\- Endpoint behavior and access-control claims should be kept aligned with the automated tests and actual implementation.



