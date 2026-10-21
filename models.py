
from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import CheckConstraint, UniqueConstraint
from flask_login import UserMixin


db = SQLAlchemy()


def utc_now():
    return datetime.now(timezone.utc)

class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)

    role = db.Column(
        db.String(20),
        nullable=False,
        default="viewer"
    )

    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime(timezone=True), default=utc_now, nullable=False)

    __table_args__ = (
        CheckConstraint(
            "role IN ('admin', 'owner', 'viewer')",
            name="valid_user_role"
        ),
    )

    documents = db.relationship(
        "Document",
        back_populates="owner",
        foreign_keys="Document.owner_id"
    )

    permissions = db.relationship(
        "Permission",
        back_populates="user",
        cascade="all, delete-orphan"
    )

    def __repr__(self):
        return f"<User {self.email}>"


class Document(db.Model):
    __tablename__ = "documents"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(100), nullable=False, default="General")

    # Internal storage key, not a public download URL.
    storage_key = db.Column(db.String(100), unique=True, nullable=False)

    content_type = db.Column(db.String(100), nullable=False)
    size_bytes = db.Column(db.BigInteger, nullable=False)

    owner_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True
    )

    created_at = db.Column(db.DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = db.Column(
        db.DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False
    )

    __table_args__ = (
        CheckConstraint("size_bytes >= 0", name="nonnegative_document_size"),
    )

    owner = db.relationship(
        "User",
        back_populates="documents",
        foreign_keys=[owner_id]
    )

    permissions = db.relationship(
        "Permission",
        back_populates="document",
        cascade="all, delete-orphan"
    )

    def __repr__(self):
        return f"<Document {self.id}: {self.title}>"


class Permission(db.Model):
    __tablename__ = "permissions"

    id = db.Column(db.Integer, primary_key=True)

    document_id = db.Column(
        db.Integer,
        db.ForeignKey("documents.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    # "read" allows reading; "edit" will also allow reading
    # once the authorization logic is implemented.
    permission_type = db.Column(db.String(10), nullable=False)

    granted_at = db.Column(db.DateTime(timezone=True), default=utc_now, nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "document_id",
            "user_id",
            name="unique_document_user_permission"
        ),
        CheckConstraint(
            "permission_type IN ('read', 'edit')",
            name="valid_permission_type"
        ),
    )

    document = db.relationship("Document", back_populates="permissions")
    user = db.relationship("User", back_populates="permissions")

    def __repr__(self):
        return (
            f"<Permission document={self.document_id} "
            f"user={self.user_id} type={self.permission_type}>"
        )


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)

    # Nullable so records can survive account or document deletion.
    actor_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )

    document_id = db.Column(
        db.Integer,
        db.ForeignKey("documents.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )

    action = db.Column(db.String(50), nullable=False)
    outcome = db.Column(db.String(20), nullable=False)
    details = db.Column(db.Text, nullable=True)

    created_at = db.Column(db.DateTime(timezone=True), default=utc_now, nullable=False)

    __table_args__ = (
        CheckConstraint(
            "outcome IN ('success', 'denied', 'failure')",
            name="valid_audit_outcome"
        ),
    )

    actor = db.relationship("User", foreign_keys=[actor_id])
    document = db.relationship("Document", foreign_keys=[document_id])

    def __repr__(self):
        return f"<AuditLog {self.id}: {self.action} ({self.outcome})>"
