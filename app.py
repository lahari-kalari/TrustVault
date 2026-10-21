
import os
from functools import wraps
from flask_wtf.csrf import CSRFProtect

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    url_for,
)
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from werkzeug.security import (
    check_password_hash,
    generate_password_hash,
)

from forms import LoginForm, RegistrationForm
from models import db, User, AuditLog


app = Flask(__name__, instance_relative_config=True)

os.makedirs(app.instance_path, exist_ok=True)

app.config["SQLALCHEMY_DATABASE_URI"] = (
    "sqlite:///" + os.path.join(app.instance_path, "trustvault.db")
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Development fallback only. Set TRUSTVAULT_SECRET_KEY
# to a strong, private value before deployment.
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


@login_manager.user_loader
def load_user(user_id):
    """Load the logged-in user from the database."""
    try:
        return db.session.get(User, int(user_id))
    except (TypeError, ValueError):
        return None


def roles_required(*allowed_roles):
    """Allow access only to logged-in users with an allowed role."""

    def decorator(view_function):
        @wraps(view_function)
        @login_required
        def wrapped_view(*args, **kwargs):
            if current_user.role not in allowed_roles:
                db.session.add(
                    AuditLog(
                        actor_id=current_user.id,
                        action="role_access_denied",
                        outcome="denied",
                        details=f"Path: {request_path()}",
                    )
                )
                db.session.commit()
                abort(403)

            return view_function(*args, **kwargs)

        return wrapped_view

    return decorator


def request_path():
    """Return the requested path for the access-denied audit record."""
    from flask import request
    return request.path


@app.route("/")
def home():
    # Preserve your existing homepage.
    return render_template("index.html")


@app.route("/health")
def health():
    return {"status": "ok", "application": "TrustVault"}


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    form = RegistrationForm()

    if form.validate_on_submit():
        name = form.name.data.strip()
        email = form.email.data.strip().lower()

        # Never accept a role from the registration form.
        # Every self-registered account starts as a viewer.
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

        # Use the same error for an unknown email and a wrong password.
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


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/admin")
@roles_required("admin")
def admin_page():
    # Placeholder admin page. The full activity view comes later.
    return render_template("admin.html")


if __name__ == "__main__":
    app.run(debug=True)
