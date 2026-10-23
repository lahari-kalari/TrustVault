# TrustVault - Secure Document Management System

TrustVault is a Flask-based document management application that provides authentication, role-based access control, private file uploads, document sharing, access revocation, and audit logging.

## Features

- **Authentication:** User registration, login, logout, and password hashing.
- **Role-based access control:** Admin, owner, and viewer roles.
- **Private document storage:** Supported file uploads with a 10 MB size limit and file validation.
- **Document management:** Search, download, edit, and delete operations subject to authorization checks.
- **Document sharing:** Grant and revoke document permissions.
- **Security controls:** CSRF protection, login rate limiting, and server-side authorization.
- **Audit trail:** Record relevant actions, denied requests, and upload failures.
- **Automated tests:** Regression tests for permissions, uploads, CSRF, rate limiting, and audit behavior.

## Technology Stack

- Python
- Flask and Flask-Login
- Flask-WTF
- Flask-SQLAlchemy and SQLAlchemy
- SQLite for local development
- PostgreSQL driver (`psycopg2-binary`)
- Gunicorn
- Pytest

## Local Installation

### 1. Clone the repository

```bash
git clone https://github.com/lahari-kalari/TrustVault.git
cd TrustVault
```

### 2. Create and activate a virtual environment

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
python -m pip install -r requirements.txt
```

### 4. Configure the secret key

Generate a random secret key:

```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```

Set it for the current PowerShell session, replacing the placeholder with the generated value:

```powershell
$env:TRUSTVAULT_SECRET_KEY = "replace-with-your-generated-secret"
```

Never commit real secrets, database files, or private uploads to Git.

### 5. Run the application

```powershell
python app.py
```

Open the local URL printed by Flask in your browser.

## Run the Tests

From the project directory, run:

```powershell
python -m pytest .\test_app.py -v
```

The latest recorded run passed all 20 tests. Run the suite again after making changes to verify the current result.

## Production Deployment Notes

TrustVault requires additional configuration before it is ready for a public production deployment.

- Set `TRUSTVAULT_SECRET_KEY` through the hosting platform's secret/environment-variable settings.
- Configure a persistent production database. PostgreSQL is a suitable option; database URL support must be implemented and tested before using it.
- Configure persistent private file storage. The current upload directory is inside Flask's instance directory, which may not persist on ephemeral hosting platforms.
- Use Gunicorn or another supported production WSGI server instead of Flask's development server.
- Configure HTTPS, secure cookie settings, backups, and appropriate access to operational logs.
- Review rate-limiting storage: the current limiter uses in-memory storage, which is not shared across multiple application workers.
- Run database migrations when changing existing schemas. `db.create_all()` creates missing tables but does not migrate existing ones.
- Do not expose private uploads through a public static directory.

**Deployment status:** The application has passing automated security regression tests, but production deployment is not verified by those tests. Confirm database configuration, persistent storage, production security settings, and hosting behavior before publishing a live instance.

## Security Documentation

- `API.md` â€” API and access-control documentation.
- `THREATS.md` â€” Threat model, mitigations, and residual risks.
- `PROMPTS.md` â€” AI-assisted development and verification log.

## Author

**K. Lahari**
Final-Year Computer Science Student (AI & ML)

GitHub: https://github.com/lahari-kalari
