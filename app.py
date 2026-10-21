
import os
import uuid
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
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from werkzeug.security import (
    check_password_hash,
    generate_password_hash,
)
from werkzeug.utils import secure_filename

from forms import LoginForm, RegistrationForm
from models import db, User, Document, Permission, AuditLog


# --------------------------------------------------
# APPLICATION CONFIGURATION
# --------------------------------------------------

app = Flask(__name__, instance_relative_config=True)

os.makedirs(app.instance_path, exist_ok=True)

UPLOAD_FOLDER = os.path.join(app.instance_path, "private_uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg", "txt", "docx"}

app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
app.config["SQLALCHEMY_DATABASE_URI"] = (
    "sqlite:///" + os.path.join(app.instance_path, "trustvault.db")
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.environ.get(
    "TRUSTVAULT_SECRET_KEY",
    "dev-only-change-this-secret-key",
)

csrf = CSRFProtect(app)
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to access this page."
login_manager.session_protection = "strong"


# --------------------------------------------------
# LOGIN AND ROLE MANAGEMENT
# --------------------------------------------------

@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except (TypeError, ValueError):
        return None


def roles_required(*allowed_roles):
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


# --------------------------------------------------
# AUDIT LOGGING
# --------------------------------------------------

def record_audit(action, outcome, document_id=None, details=None):
    db.session.add(
        AuditLog(
            actor_id=(
                current_user.id
                if current_user.is_authenticated
                else None
            ),
            document_id=document_id,
            action=action,
            outcome=outcome,
            details=details,
        )
    )
    db.session.commit()


# --------------------------------------------------
# DOCUMENT AUTHORIZATION
# --------------------------------------------------

def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


def can_read_document(document):
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


# --------------------------------------------------
# HOME
# --------------------------------------------------

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/health")
def health():
    return {"status": "ok", "application": "TrustVault"}


# --------------------------------------------------
# REGISTRATION
# --------------------------------------------------

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
            password_hash=generate_password_hash(form.password.data),
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
            flash("Account created. You can now log in.", "success")
            return redirect(url_for("login"))

    return render_template("register.html", form=form)


# --------------------------------------------------
# LOGIN AND LOGOUT
# --------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
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
            flash("Invalid email or password.", "error")
        else:
            login_user(user, remember=False, fresh=True)
            flash("You are now logged in.", "success")
            return redirect(url_for("dashboard"))

    return render_template("login.html", form=form)


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


# --------------------------------------------------
# DASHBOARD: OWNED AND SHARED DOCUMENTS
# --------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():
    documents = (
        Document.query
        .filter_by(owner_id=current_user.id)
        .order_by(Document.created_at.desc())
        .all()
    )

    shared_permissions = Permission.query.filter_by(
        user_id=current_user.id
    ).all()

    shared_documents = []

    for permission in shared_permissions:
        document = db.session.get(Document, permission.document_id)

        if document is not None and document.owner_id != current_user.id:
            shared_documents.append(
                (document, permission.permission_type)
            )

    return render_template(
        "dashboard.html",
        documents=documents,
        shared_documents=shared_documents,
    )


# --------------------------------------------------
# ADMIN PAGE
# --------------------------------------------------

@app.route("/admin")
@roles_required("admin")
def admin_page():
    return render_template("admin.html")


# --------------------------------------------------
# UPLOAD DOCUMENT
# --------------------------------------------------

@app.route("/documents/upload", methods=["POST"])
@login_required
def upload_document():
    uploaded_file = request.files.get("file")

    if uploaded_file is None or not uploaded_file.filename:
        record_audit(
            "document_upload",
            "failure",
            details="No file was selected.",
        )
        flash("Please select a file to upload.", "error")
        return redirect(url_for("dashboard"))

    original_filename = secure_filename(uploaded_file.filename)

    if not original_filename or not allowed_file(original_filename):
        record_audit(
            "document_upload",
            "failure",
            details="Rejected file extension.",
        )
        flash("This file type is not allowed.", "error")
        return redirect(url_for("dashboard"))

    storage_key = uuid.uuid4().hex
    storage_path = os.path.join(UPLOAD_FOLDER, storage_key)

    try:
        uploaded_file.save(storage_path)
        size_bytes = os.path.getsize(storage_path)

        if size_bytes == 0:
            os.remove(storage_path)
            record_audit(
                "document_upload",
                "failure",
                details="Empty file rejected.",
            )
            flash("Empty files are not allowed.", "error")
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

        if os.path.exists(storage_path):
            os.remove(storage_path)

        app.logger.exception("Document upload failed")
        flash("The upload failed. Please try again.", "error")
        return redirect(url_for("dashboard"))

    flash("Document uploaded successfully.", "success")
    return redirect(url_for("dashboard"))


# --------------------------------------------------
# DOWNLOAD DOCUMENT
# --------------------------------------------------

@app.route("/documents/<int:document_id>/download", methods=["GET"])
@login_required
def download_document(document_id):
    document = db.session.get(Document, document_id)

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

    storage_path = os.path.join(UPLOAD_FOLDER, document.storage_key)

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


# --------------------------------------------------
# SHARE DOCUMENT
# --------------------------------------------------

@app.route("/documents/<int:document_id>/share", methods=["POST"])
@login_required
def share_document(document_id):
    document = db.session.get(Document, document_id)

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

    email = request.form.get("email", "").strip().lower()
    permission_type = request.form.get("permission_type", "")

    if permission_type not in ("read", "edit"):
        abort(400, description="Invalid permission type.")

    if not email or len(email) > 255:
        abort(400, description="Enter a valid email address.")

    recipient = db.session.scalar(
        select(User).where(
            User.email == email,
            User.is_active.is_(True),
        )
    )

    if recipient is None:
        flash("No active account was found for that email.", "error")
        return redirect(url_for("dashboard"))

    if recipient.id == current_user.id:
        flash("You already own this document.", "error")
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

    flash("Document access updated successfully.", "success")
    return redirect(url_for("dashboard"))


# --------------------------------------------------
# REVOKE DOCUMENT ACCESS
# --------------------------------------------------

@app.route(
    "/documents/<int:document_id>/revoke/<int:user_id>",
    methods=["POST"],
)
@login_required
def revoke_document_access(document_id, user_id):
    document = db.session.get(Document, document_id)

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
        flash("That user has no permission to revoke.", "error")
        return redirect(url_for("dashboard"))

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

    flash("Document access revoked.", "success")
    return redirect(url_for("dashboard"))


# --------------------------------------------------
# RUN APPLICATION
# --------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True)
