import os
import uuid
import zipfile
from functools import wraps

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_wtf.csrf import CSRFProtect
from sqlalchemy import select, or_, event
from sqlalchemy.engine import Engine
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.security import (
    check_password_hash,
    generate_password_hash,
)
from werkzeug.utils import secure_filename

from forms import LoginForm, RegistrationForm
from models import db, User, Document, Permission, AuditLog


# ==================================================
# 1. APPLICATION CONFIGURATION
# ==================================================

app = Flask(__name__, instance_relative_config=True)
rate_limit_storage = os.environ.get(
    "REDIS_URL",
    "memory://",
)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri=rate_limit_storage,
    enabled=not app.config.get("TESTING", False),
)

os.makedirs(app.instance_path, exist_ok=True)

UPLOAD_FOLDER = os.path.join(
    app.instance_path,
    "private_uploads",
)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = {
    "pdf", "png", "jpg", "jpeg", "txt", "docx"
}

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE

database_url = os.environ.get("DATABASE_URL")

if database_url:
    # Support PostgreSQL URLs supplied by deployment platforms.
    if database_url.startswith("postgres://"):
        database_url = database_url.replace(
            "postgres://",
            "postgresql://",
            1,
        )

    app.config["SQLALCHEMY_DATABASE_URI"] = database_url
else:
    # Keep the existing SQLite database for local development.
    app.config["SQLALCHEMY_DATABASE_URI"] = (
        "sqlite:///" + os.path.join(app.instance_path, "trustvault.db")
    )

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.config["SECRET_KEY"] = os.environ.get(
    "TRUSTVAULT_SECRET_KEY"
)

if not app.config["SECRET_KEY"]:
    if os.environ.get("FLASK_ENV") == "production":
        raise RuntimeError(
            "Set TRUSTVAULT_SECRET_KEY before starting in production."
        )

    # Development fallback only. Set a real secret for deployment.
    app.config["SECRET_KEY"] = (
        "dev-only-change-this-secret-key"
    )

csrf = CSRFProtect(app)


db.init_app(app)


@event.listens_for(Engine, "connect")
def enable_sqlite_foreign_keys(
    dbapi_connection,
    connection_record,
):
    if dbapi_connection.__class__.__module__ == "sqlite3":
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = (
    "Please log in to access this page."
)
login_manager.session_protection = "strong"


# ==================================================
# 2. ERROR HANDLING
# ==================================================

@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(error):
    record_audit(
        "document_upload",
        "failure",
        details="Request exceeded the upload size limit.",
    )

    flash(
        "The request exceeds the 10 MB upload limit.",
        "error",
    )

    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


# ==================================================
# 3. LOGIN AND ROLE MANAGEMENT
# ==================================================

@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except (TypeError, ValueError):
        return None


def roles_required(*allowed_roles):
    """Allow access only to users with specified roles."""

    def decorator(view_function):

        @wraps(view_function)
        @login_required
        def wrapped_view(*args, **kwargs):
            if current_user.role not in allowed_roles:
                record_audit(
                    "role_access_denied",
                    "denied",
                    details=f"Path: {request.path}",
                )
                abort(403)

            return view_function(*args, **kwargs)

        return wrapped_view

    return decorator


# ==================================================
# 4. AUDIT LOGGING
# ==================================================

def record_audit(
    action,
    outcome,
    document_id=None,
    details=None,
):
    """
    Save an audit event.

    This helper commits its own transaction. For operations
    that must be atomic with their audit entry, add AuditLog
    directly to the current session and commit once.
    """
    try:
        actor_id = (
            current_user.id
            if current_user.is_authenticated
            else None
        )

        entry = AuditLog(
            actor_id=actor_id,
            document_id=document_id,
            action=action,
            outcome=outcome,
            details=details,
        )

        db.session.add(entry)
        db.session.commit()

    except Exception:
        db.session.rollback()
        app.logger.exception(
            "Failed to save audit log: %s",
            action,
        )


# ==================================================
# 5. FILE VALIDATION
# ==================================================

def allowed_file(filename):
    """Check whether the file extension is allowed."""

    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )


def has_valid_file_signature(file_path, filename):
    """
    Perform basic file-format validation.

    This does not replace antivirus or malware scanning.
    """

    if "." not in filename:
        return False

    extension = filename.rsplit(".", 1)[1].lower()

    signatures = {
        "pdf": b"%PDF-",
        "png": b"\x89PNG\r\n\x1a\n",
        "jpg": b"\xff\xd8\xff",
        "jpeg": b"\xff\xd8\xff",
    }

    try:
        with open(file_path, "rb") as file:
            header = file.read(16)

        # Validate PDF, PNG and JPEG signatures.
        if extension in signatures:
            return header.startswith(signatures[extension])

        # Basic TXT check: reject NUL bytes in the initial sample.
        if extension == "txt":
            return b"\x00" not in header

        # DOCX files are ZIP archives containing Office XML files.
        if extension == "docx":
            if not header.startswith(b"PK"):
                return False

            with zipfile.ZipFile(file_path, "r") as archive:
                names = set(archive.namelist())

                return (
                    "[Content_Types].xml" in names
                    and "word/document.xml" in names
                )

        return False

    except (
        OSError,
        zipfile.BadZipFile,
        ValueError,
    ):
        return False


# ==================================================
# 6. DOCUMENT AUTHORIZATION
# ==================================================

def can_read_document(document):
    """Owners and users with read/edit permission can download."""

    if document.owner_id == current_user.id:
        return True

    permission = db.session.scalar(
        select(Permission).where(
            Permission.document_id == document.id,
            Permission.user_id == current_user.id,
            Permission.permission_type.in_(["read", "edit"]),
        )
    )

    return permission is not None


def can_edit_document(document):
    """Only the owner or a user with edit permission can edit."""

    if document.owner_id == current_user.id:
        return True

    permission = db.session.scalar(
        select(Permission).where(
            Permission.document_id == document.id,
            Permission.user_id == current_user.id,
            Permission.permission_type == "edit",
        )
    )

    return permission is not None


# ==================================================
# 7. HOME AND HEALTH CHECK
# ==================================================

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/health")
def health():
    return {
        "status": "ok",
        "application": "TrustVault",
    }


# ==================================================
# 8. USER REGISTRATION
# ==================================================

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    form = RegistrationForm()

    if form.validate_on_submit():
        name = form.name.data.strip()
        email = form.email.data.strip().lower()

        user = User(
            name=name,
            email=email,
            password_hash=generate_password_hash(
                form.password.data
            ),
            role="viewer",
        )

        db.session.add(user)

        try:
            db.session.commit()

        except IntegrityError:
            db.session.rollback()
            form.email.errors.append(
                "An account with this email may already exist."
            )

        else:
            flash(
                "Account created. You can now log in.",
                "success",
            )
            return redirect(url_for("login"))

    return render_template(
        "register.html",
        form=form,
    )


# ==================================================
# 9. LOGIN AND LOGOUT
# ==================================================

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    form = LoginForm()

    if form.validate_on_submit():
        email = form.email.data.strip().lower()

        user = db.session.scalar(
            select(User).where(User.email == email)
        )

        if (
            user is None
            or not user.is_active
            or not check_password_hash(
                user.password_hash,
                form.password.data,
            )
        ):
            flash(
                "Invalid email or password.",
                "error",
            )

        else:
            login_user(
                user,
                remember=False,
                fresh=True,
            )

            flash(
                "You are now logged in.",
                "success",
            )
            return redirect(url_for("dashboard"))

    return render_template(
        "login.html",
        form=form,
    )


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()

    flash(
        "You have been logged out.",
        "success",
    )

    return redirect(url_for("login"))


# ==================================================
# 10. DASHBOARD AND DOCUMENT SEARCH
# ==================================================

@app.route("/dashboard")
@login_required
def dashboard():
    search_query = request.args.get("q", "").strip()

    # Documents owned by the logged-in user.
    owned_query = Document.query.filter_by(
        owner_id=current_user.id
    )

    # Documents explicitly shared with the logged-in user.
    shared_query = (
        Document.query
        .join(
            Permission,
            Permission.document_id == Document.id,
        )
        .join(
            User,
            User.id == Permission.user_id,
        )
        .filter(
            Permission.user_id == current_user.id,
            User.is_active.is_(True),
        )
    )

    if search_query:
        pattern = f"%{search_query}%"

        search_filter = or_(
            Document.title.ilike(pattern),
            Document.original_filename.ilike(pattern),
            Document.category.ilike(pattern),
            Document.owner.has(
                User.name.ilike(pattern)
            ),
        )

        owned_query = owned_query.filter(search_filter)
        shared_query = shared_query.filter(search_filter)

    documents = owned_query.order_by(
        Document.created_at.desc()
    ).all()

    shared_permissions = shared_query.order_by(
        Document.created_at.desc()
    ).all()

    shared_documents = []

    for document in shared_permissions:
        permission = db.session.scalar(
            select(Permission).where(
                Permission.document_id == document.id,
                Permission.user_id == current_user.id,
            )
        )

        if permission is not None:
            shared_documents.append(
                (document, permission.permission_type)
            )

    return render_template(
        "dashboard.html",
        documents=documents,
        shared_documents=shared_documents,
        search_query=search_query,
    )


# ==================================================
# 11. ADMIN PAGE
# ==================================================

@app.route("/admin")
@roles_required("admin")
def admin_page():
    return render_template("admin.html")


# ==================================================
# 12. UPLOAD DOCUMENT
# ==================================================

@app.route("/documents/upload", methods=["POST"])
@login_required
def upload_document():
    uploaded_file = request.files.get("file")

    if (
        uploaded_file is None
        or not uploaded_file.filename
    ):
        record_audit(
            "document_upload",
            "failure",
            details="No file was selected.",
        )

        flash(
            "Please select a file to upload.",
            "error",
        )
        return redirect(url_for("dashboard"))

    original_filename = secure_filename(
        uploaded_file.filename
    )

    if (
        not original_filename
        or not allowed_file(original_filename)
    ):
        record_audit(
            "document_upload",
            "failure",
            details="Rejected file extension.",
        )

        flash(
            "This file type is not allowed.",
            "error",
        )
        return redirect(url_for("dashboard"))

    storage_key = uuid.uuid4().hex

    storage_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        storage_key,
    )

    try:
        os.makedirs(
            app.config["UPLOAD_FOLDER"],
            exist_ok=True,
        )

        uploaded_file.save(storage_path)

        size_bytes = os.path.getsize(storage_path)

        if size_bytes == 0:
            os.remove(storage_path)

            record_audit(
                "document_upload",
                "failure",
                details="Empty file rejected.",
            )

            flash(
                "Empty files are not allowed.",
                "error",
            )
            return redirect(url_for("dashboard"))

        if size_bytes > app.config["MAX_CONTENT_LENGTH"]:
            os.remove(storage_path)

            record_audit(
                "document_upload",
                "failure",
                details="File exceeded the upload size limit.",
            )

            flash(
                "File exceeds the 10 MB upload limit.",
                "error",
            )
            return redirect(url_for("dashboard"))

        if not has_valid_file_signature(
            storage_path,
            original_filename,
        ):
            os.remove(storage_path)

            record_audit(
                "document_upload",
                "failure",
                details="File signature validation failed.",
            )

            flash(
                "The file content does not match its extension.",
                "error",
            )
            return redirect(url_for("dashboard"))

        document = Document(
            title=original_filename[:200],
            original_filename=original_filename[:255],
            category="General",
            storage_key=storage_key,
            content_type="application/octet-stream",
            size_bytes=size_bytes,
            owner_id=current_user.id,
        )

        db.session.add(document)
        db.session.flush()

        # Save the document and success audit in one transaction.
        db.session.add(
            AuditLog(
                actor_id=current_user.id,
                document_id=document.id,
                action="document_upload",
                outcome="success",
                details=f"Uploaded {original_filename}",
            )
        )

        db.session.commit()

    except Exception:
        db.session.rollback()

        if os.path.isfile(storage_path):
            try:
                os.remove(storage_path)
            except OSError:
                app.logger.exception(
                    "Failed to clean up an incomplete upload."
                )

        app.logger.exception("Document upload failed.")

        flash(
            "The upload failed. Please try again.",
            "error",
        )
        return redirect(url_for("dashboard"))

    flash(
        "Document uploaded successfully.",
        "success",
    )

    return redirect(url_for("dashboard"))


# ==================================================
# 13. DOWNLOAD DOCUMENT
# ==================================================

@app.route(
    "/documents/<int:document_id>/download",
    methods=["GET"],
)
@login_required
def download_document(document_id):
    document = db.session.get(
        Document,
        document_id,
    )

    if document is None:
        abort(404)

    if not can_read_document(document):
        record_audit(
            "document_download",
            "denied",
            document_id=document.id,
            details="User lacks document read permission.",
        )
        abort(403)

    storage_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        document.storage_key,
    )

    if not os.path.isfile(storage_path):
        record_audit(
            "document_download",
            "failure",
            document_id=document.id,
            details="Stored file is missing.",
        )
        abort(404)

    record_audit(
        "document_download",
        "success",
        document_id=document.id,
        details="Authorized document download.",
    )

    return send_file(
        storage_path,
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name=document.original_filename,
    )


# ==================================================
# 14. SHARE DOCUMENT
# ==================================================

@app.route(
    "/documents/<int:document_id>/share",
    methods=["POST"],
)
@login_required
def share_document(document_id):
    document = db.session.get(
        Document,
        document_id,
    )

    if document is None:
        abort(404)

    if document.owner_id != current_user.id:
        record_audit(
            "permission_grant",
            "denied",
            document_id=document.id,
            details="Only the document owner may share it.",
        )
        abort(403)

    email = request.form.get(
        "email", ""
    ).strip().lower()

    permission_type = request.form.get(
        "permission_type", ""
    )

    if permission_type not in ("read", "edit"):
        abort(
            400,
            description="Invalid permission type.",
        )

    if (
        not email
        or len(email) > 255
        or "@" not in email
    ):
        abort(
            400,
            description="Enter a valid email address.",
        )

    recipient = db.session.scalar(
        select(User).where(
            User.email == email,
            User.is_active.is_(True),
        )
    )

    if recipient is None:
        flash(
            "No active account was found for that email.",
            "error",
        )
        return redirect(url_for("dashboard"))

    if recipient.id == current_user.id:
        flash(
            "You already own this document.",
            "error",
        )
        return redirect(url_for("dashboard"))

    permission = db.session.scalar(
        select(Permission).where(
            Permission.document_id == document.id,
            Permission.user_id == recipient.id,
        )
    )

    if permission is None:
        permission = Permission(
            document_id=document.id,
            user_id=recipient.id,
            permission_type=permission_type,
        )
        db.session.add(permission)
        action = "permission_grant"

    else:
        permission.permission_type = permission_type
        action = "permission_update"

    db.session.add(
        AuditLog(
            actor_id=current_user.id,
            document_id=document.id,
            action=action,
            outcome="success",
            details=(
                f"Permission {permission_type} assigned "
                f"to user ID {recipient.id}."
            ),
        )
    )

    db.session.commit()

    flash(
        "Document access updated successfully.",
        "success",
    )

    return redirect(url_for("dashboard"))


# ==================================================
# 15. REVOKE DOCUMENT ACCESS
# ==================================================

@app.route(
    "/documents/<int:document_id>/revoke/<int:user_id>",
    methods=["POST"],
)
@login_required
def revoke_document_access(document_id, user_id):
    document = db.session.get(
        Document,
        document_id,
    )

    if document is None:
        abort(404)

    if document.owner_id != current_user.id:
        record_audit(
            "permission_revoke",
            "denied",
            document_id=document.id,
            details="Only the document owner may revoke access.",
        )
        abort(403)

    permission = db.session.scalar(
        select(Permission).where(
            Permission.document_id == document.id,
            Permission.user_id == user_id,
        )
    )

    if permission is None:
        flash(
            "That user has no permission to revoke.",
            "error",
        )
        return redirect(url_for("dashboard"))

    try:
        db.session.add(
            AuditLog(
                actor_id=current_user.id,
                document_id=document.id,
                action="permission_revoke",
                outcome="success",
                details=f"Access revoked for user ID {user_id}.",
            )
        )

        db.session.delete(permission)
        db.session.commit()

    except Exception:
        db.session.rollback()
        app.logger.exception("Permission revocation failed.")

        flash(
            "Could not revoke access. Please try again.",
            "error",
        )
        return redirect(url_for("dashboard"))

    flash(
        "Document access revoked.",
        "success",
    )

    return redirect(url_for("dashboard"))


# ==================================================
# 16. EDIT DOCUMENT METADATA
# ==================================================

@app.route(
    "/documents/<int:document_id>/edit",
    methods=["POST"],
)
@login_required
def edit_document(document_id):
    document = db.session.get(
        Document,
        document_id,
    )

    if document is None:
        abort(404)

    # Only the owner can edit metadata through this route.
    if document.owner_id != current_user.id:
        record_audit(
            "edit_document",
            "denied",
            document_id=document.id,
            details="Unauthorized metadata edit attempt.",
        )
        abort(403)

    title = request.form.get(
        "title", ""
    ).strip()

    category = request.form.get(
        "category", ""
    ).strip()

    if not title or len(title) > 200:
        flash(
            "Title must contain 1–200 characters.",
            "error",
        )
        return redirect(url_for("dashboard"))

    if not category or len(category) > 100:
        flash(
            "Category must contain 1–100 characters.",
            "error",
        )
        return redirect(url_for("dashboard"))

    try:
        document.title = title
        document.category = category

        db.session.add(
            AuditLog(
                actor_id=current_user.id,
                document_id=document.id,
                action="edit_document",
                outcome="success",
                details="Document title/category updated.",
            )
        )

        db.session.commit()

    except Exception:
        db.session.rollback()
        app.logger.exception("Metadata update failed.")

        flash(
            "Could not update document details.",
            "error",
        )
        return redirect(url_for("dashboard"))

    flash(
        "Document details updated successfully.",
        "success",
    )

    return redirect(url_for("dashboard"))


# ==================================================
# 17. DELETE DOCUMENT
# ==================================================

@app.route(
    "/documents/<int:document_id>/delete",
    methods=["POST"],
)
@login_required
def delete_document(document_id):
    document = db.session.get(
        Document,
        document_id,
    )

    if document is None:
        abort(404)

    # Only the owner can delete a document.
    if document.owner_id != current_user.id:
        record_audit(
            "delete_document",
            "denied",
            document_id=document.id,
            details="Unauthorized deletion attempt.",
        )
        abort(403)

    deleted_document_id = document.id

    storage_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        document.storage_key,
    )

    try:
        # Remove document permissions.
        Permission.query.filter_by(
            document_id=document.id
        ).delete(synchronize_session=False)

        # Keep the deletion event without a foreign key
        # referencing the document being deleted.
        db.session.add(
            AuditLog(
                actor_id=current_user.id,
                document_id=None,
                action="delete_document",
                outcome="success",
                details=(
                    f"Deleted document ID {deleted_document_id}."
                ),
            )
        )

        db.session.delete(document)
        db.session.commit()

    except Exception:
        db.session.rollback()
        app.logger.exception("Document deletion failed.")

        flash(
            "Could not delete the document. Please try again.",
            "error",
        )
        return redirect(url_for("dashboard"))

    # Remove the private file after the database commit.
    if os.path.isfile(storage_path):
        try:
            os.remove(storage_path)

        except OSError:
            app.logger.exception(
                "Database record deleted, but private file "
                "cleanup failed."
            )

            flash(
                "Document record deleted, but file cleanup "
                "needs attention.",
                "error",
            )
            return redirect(url_for("dashboard"))

    flash(
        "Document deleted successfully.",
        "success",
    )

    return redirect(url_for("dashboard"))


# ==================================================
# 18. CREATE MISSING TABLES AND RUN
# ==================================================

with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(debug=True)