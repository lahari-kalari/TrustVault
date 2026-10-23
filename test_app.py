
import os

import pytest
from werkzeug.security import generate_password_hash
from sqlalchemy.exc import IntegrityError

from app import app, db, record_audit, limiter
from models import User, Document, Permission, AuditLog
@pytest.fixture
def client():
    app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
        RATELIMIT_ENABLED=False,
        SECRET_KEY="test-secret-key",
        SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
        UPLOAD_FOLDER="test_private_uploads",
    )

    limiter.enabled = False
    limiter.reset()

    with app.app_context():
        db.drop_all()
        db.create_all()

        owner = User(
            name="Test Owner",
            email="owner@example.com",
            password_hash=generate_password_hash(
                "OwnerTestPass123!"
            ),
            role="owner",
            is_active=True,
        )

        viewer = User(
            name="Test Viewer",
            email="viewer@example.com",
            password_hash=generate_password_hash(
                "ViewerTestPass123!"
            ),
            role="viewer",
            is_active=True,
        )
        admin = User(
            name="Test Administrator",
            email="admin@example.com",
            password_hash=generate_password_hash(
                "AdminTestPass123!"
            ),
            role="admin",
            is_active=True,
        )

        db.session.add_all([owner, viewer, admin])
        db.session.commit()

        yield app.test_client()

        db.session.remove()
        db.drop_all()


def login(client, email, password):
    return client.post(
        "/login",
        data={
            "email": email,
            "password": password,
        },
        follow_redirects=True,
    )


def test_dashboard_requires_login(client):
    response = client.get("/dashboard")

    assert response.status_code == 302



def test_viewer_cannot_access_admin_page(client):
    from models import AuditLog

    login(
        client,
        "viewer@example.com",
        "ViewerTestPass123!",
    )

    response = client.get("/admin")

    assert response.status_code == 403

    with app.app_context():
        event = (
            db.session.query(AuditLog)
            .filter_by(
                action="role_access_denied",
                outcome="denied",
            )
            .order_by(AuditLog.id.desc())
            .first()
        )

        assert event is not None
        assert event.actor_id is not None
        assert "/admin" in event.details



def test_user_cannot_download_private_document(client):
    with app.app_context():
        owner = User.query.filter_by(
            email="owner@example.com"
        ).first()

        document = Document(
            title="Private Test Document",
            original_filename="private.txt",
            category="General",
            storage_key="private-test-file.txt",
            content_type="text/plain",
            size_bytes=12,
            owner_id=owner.id,
        )

        db.session.add(document)
        db.session.commit()

        document_id = document.id

        upload_folder = app.config["UPLOAD_FOLDER"]
        os.makedirs(upload_folder, exist_ok=True)

        with open(
            os.path.join(
                upload_folder,
                "private-test-file.txt",
            ),
            "w",
            encoding="utf-8",
        ) as file:
            file.write("Private data")

    login(
        client,
        "viewer@example.com",
        "ViewerTestPass123!",
    )

    response = client.get(
        f"/documents/{document_id}/download"
    )

    assert response.status_code == 403


def test_shared_user_can_download_document(client):
    with app.app_context():
        owner = User.query.filter_by(
            email="owner@example.com"
        ).first()

        viewer = User.query.filter_by(
            email="viewer@example.com"
        ).first()

        document = Document(
            title="Shared Test Document",
            original_filename="shared.txt",
            category="General",
            storage_key="shared-test-file.txt",
            content_type="text/plain",
            size_bytes=11,
            owner_id=owner.id,
        )

        db.session.add(document)
        db.session.commit()

        permission = Permission(
            document_id=document.id,
            user_id=viewer.id,
            permission_type="read",
        )

        db.session.add(permission)
        db.session.commit()

        document_id = document.id

        upload_folder = app.config["UPLOAD_FOLDER"]
        os.makedirs(upload_folder, exist_ok=True)

        with open(
            os.path.join(
                upload_folder,
                "shared-test-file.txt",
            ),
            "w",
            encoding="utf-8",
        ) as file:
            file.write("Shared data")

    login(
        client,
        "viewer@example.com",
        "ViewerTestPass123!",
    )

    response = client.get(
        f"/documents/{document_id}/download"
    )

    assert response.status_code == 200
    assert response.data == b"Shared data"


def test_revoked_user_cannot_download_document(client):
    with app.app_context():
        owner = User.query.filter_by(
            email="owner@example.com"
        ).first()

        viewer = User.query.filter_by(
            email="viewer@example.com"
        ).first()

        document = Document(
            title="Revocation Test",
            original_filename="revocation.txt",
            category="General",
            storage_key="revocation-test-file.txt",
            content_type="text/plain",
            size_bytes=15,
            owner_id=owner.id,
        )

        db.session.add(document)
        db.session.commit()

        permission = Permission(
            document_id=document.id,
            user_id=viewer.id,
            permission_type="read",
        )

        db.session.add(permission)
        db.session.commit()

        # Save IDs while the database session is active.
        document_id = document.id
        viewer_id = viewer.id

        upload_folder = app.config["UPLOAD_FOLDER"]
        os.makedirs(upload_folder, exist_ok=True)

        with open(
            os.path.join(
                upload_folder,
                "revocation-test-file.txt",
            ),
            "w",
            encoding="utf-8",
        ) as file:
            file.write("Revocation test")

    login(
        client,
        "viewer@example.com",
        "ViewerTestPass123!",
    )

    # The viewer should initially have access.
    response = client.get(
        f"/documents/{document_id}/download"
    )

    assert response.status_code == 200

    # Revoke the viewer's read permission.
    with app.app_context():
        permission = Permission.query.filter_by(
            document_id=document_id,
            user_id=viewer_id,
        ).first()

        assert permission is not None

        db.session.delete(permission)
        db.session.commit()

    # The viewer should no longer have access.
    response = client.get(
        f"/documents/{document_id}/download"
    )

    assert response.status_code == 403


def test_owner_can_share_document(client):
    with app.app_context():
        owner = User.query.filter_by(
            email="owner@example.com"
        ).first()

        viewer = User.query.filter_by(
            email="viewer@example.com"
        ).first()

        document = Document(
            title="Share Route Test",
            original_filename="share-route.txt",
            category="General",
            storage_key="share-route-test.txt",
            content_type="text/plain",
            size_bytes=12,
            owner_id=owner.id,
        )

        db.session.add(document)
        db.session.commit()

        document_id = document.id
        viewer_email = viewer.email

    login(
        client,
        "owner@example.com",
        "OwnerTestPass123!",
    )

    # Submit the sharing form.
    response = client.post(
        f"/documents/{document_id}/share",
        data={
            "email": viewer_email,
            "permission_type": "read",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200

    with app.app_context():
        permission = Permission.query.filter_by(
            document_id=document_id,
            user_id=viewer.id,
        ).first()

        assert permission is not None
        assert permission.permission_type == "read"


def test_owner_can_revoke_document_access(client):
    with app.app_context():
        owner = User.query.filter_by(
            email="owner@example.com"
        ).first()

        viewer = User.query.filter_by(
            email="viewer@example.com"
        ).first()

        document = Document(
            title="Revoke Route Test",
            original_filename="revoke-route.txt",
            category="General",
            storage_key="revoke-route-test.txt",
            content_type="text/plain",
            size_bytes=12,
            owner_id=owner.id,
        )

        db.session.add(document)
        db.session.commit()

        document_id = document.id
        viewer_id = viewer.id

        permission = Permission(
            document_id=document_id,
            user_id=viewer_id,
            permission_type="read",
        )

        db.session.add(permission)
        db.session.commit()

    login(
        client,
        "owner@example.com",
        "OwnerTestPass123!",
    )

    # Submit the revoke request.
    response = client.post(
        f"/documents/{document_id}/revoke/{viewer_id}",
        follow_redirects=True,
    )

    assert response.status_code == 200

    with app.app_context():
        permission = Permission.query.filter_by(
            document_id=document_id,
            user_id=viewer_id,
        ).first()

        assert permission is None
        

from io import BytesIO


def test_upload_rejects_unsupported_file_type(client):
    login(
        client,
        "owner@example.com",
        "OwnerTestPass123!",
    )

    response = client.post(
        "/documents/upload",
        data={
            "title": "Unsupported File",
            "category": "General",
            "file": (
                BytesIO(b"test executable content"),
                "malicious.exe",
            ),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    # The application should reject the unsupported extension.
    assert response.status_code == 200

    with app.app_context():
        document = Document.query.filter_by(
            original_filename="malicious.exe"
        ).first()

        assert document is None


def test_upload_accepts_text_file(client):
    login(
        client,
        "owner@example.com",
        "OwnerTestPass123!",
    )

    response = client.post(
        "/documents/upload",
        data={
            "title": "Valid Test Document",
            "category": "General",
            "file": (
                BytesIO(b"This is a valid test document."),
                "valid-test.txt",
            ),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert response.status_code == 200

    with app.app_context():
        document = Document.query.filter_by(
            original_filename="valid-test.txt"
        ).first()

        assert document is not None
        assert document.title == "valid-test.txt"
        
        

def test_upload_rejects_invalid_text_signature(client):
    login(
        client,
        "owner@example.com",
        "OwnerTestPass123!",
    )

    response = client.post(
        "/documents/upload",
        data={
            "file": (
                BytesIO(b"\x00\x01\x02\x03"),
                "invalid.txt",
            ),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert response.status_code == 200

    with app.app_context():
        document = Document.query.filter_by(
            original_filename="invalid.txt"
        ).first()

        assert document is None


def test_upload_rejects_empty_file(client):
    login(
        client,
        "owner@example.com",
        "OwnerTestPass123!",
    )

    response = client.post(
        "/documents/upload",
        data={
            "file": (
                BytesIO(b""),
                "empty.txt",
            ),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert response.status_code == 200

    with app.app_context():
        document = Document.query.filter_by(
            original_filename="empty.txt"
        ).first()

        assert document is None



def test_audit_event_is_persisted(client):

    login(
        client,
        "viewer@example.com",
        "ViewerTestPass123!",
    )

    response = client.get("/admin")

    assert response.status_code == 403

    with app.app_context():
        event = (
            AuditLog.query
            .filter_by(
                action="role_access_denied",
                outcome="denied",
            )
            .order_by(AuditLog.id.desc())
            .first()
        )

        assert event is not None
        assert event.actor_id is not None
        assert "/admin" in event.details
        


def test_audit_log_rejects_invalid_outcome(client):
    with app.app_context():
        event = AuditLog(
            action="security_test",
            outcome="unknown",
            details="Testing invalid audit outcome",
        )

        db.session.add(event)

        with pytest.raises(IntegrityError):
            db.session.commit()

        db.session.rollback()

        event_count = AuditLog.query.filter_by(
            action="security_test"
        ).count()

        assert event_count == 0

def test_audit_log_survives_user_deletion(client):
    with app.app_context():
        owner = User.query.filter_by(
            email="owner@example.com"
        ).first()
        assert owner is not None

        owner_id = owner.id

        event = AuditLog(
            actor_id=owner_id,
            action="user_deletion_test",
            outcome="success",
            details="Testing audit retention after user deletion",
        )

        db.session.add(event)
        db.session.commit()

        event_id = event.id

        db.session.delete(owner)
        db.session.commit()

        saved_event = db.session.get(AuditLog, event_id)

        assert saved_event is not None
        assert saved_event.action == "user_deletion_test"
        assert saved_event.actor_id is None

def test_viewer_cannot_edit_another_users_document(client):
    with app.app_context():
        owner = User.query.filter_by(
            email="owner@example.com"
        ).first()

        document = Document(
            title="Original Title",
            original_filename="original.txt",
            category="General",
            storage_key="edit-security-test.txt",
            content_type="text/plain",
            size_bytes=12,
            owner_id=owner.id,
        )

        db.session.add(document)
        db.session.commit()
        document_id = document.id

    login(
        client,
        "viewer@example.com",
        "ViewerTestPass123!",
    )

    response = client.post(
        f"/documents/{document_id}/edit",
        data={
            "title": "Unauthorized Change",
            "category": "Changed",
        },
    )

    assert response.status_code == 403

    with app.app_context():
        document = db.session.get(Document, document_id)

        assert document is not None
        assert document.title == "Original Title"
        assert document.category == "General"

        event = AuditLog.query.filter_by(
            action="edit_document",
            outcome="denied",
            document_id=document_id,
        ).first()

        assert event is not None


def test_viewer_cannot_delete_another_users_document(client):
    with app.app_context():
        owner = User.query.filter_by(
            email="owner@example.com"
        ).first()

        document = Document(
            title="Protected Document",
            original_filename="protected.txt",
            category="General",
            storage_key="delete-security-test.txt",
            content_type="text/plain",
            size_bytes=10,
            owner_id=owner.id,
        )

        db.session.add(document)
        db.session.commit()
        document_id = document.id

    login(
        client,
        "viewer@example.com",
        "ViewerTestPass123!",
    )

    response = client.post(
        f"/documents/{document_id}/delete",
        follow_redirects=False,
    )

    assert response.status_code == 403

    with app.app_context():
        document = db.session.get(Document, document_id)

        assert document is not None
        assert document.title == "Protected Document"

        event = AuditLog.query.filter_by(
            action="delete_document",
            outcome="denied",
            document_id=document_id,
        ).first()

        assert event is not None





def test_record_audit_handles_database_commit_failure(
    client,
    monkeypatch,
    caplog,
):
    def fail_commit():
        raise RuntimeError("Simulated audit database failure")

    rollback_called = False
    original_rollback = db.session.rollback

    def track_rollback():
        nonlocal rollback_called
        rollback_called = True
        original_rollback()

    monkeypatch.setattr(db.session, "commit", fail_commit)
    monkeypatch.setattr(db.session, "rollback", track_rollback)
    with app.test_request_context("/"):
        with app.app_context():
            with caplog.at_level("ERROR"):
                record_audit(
                    action="audit_failure_test",
                    outcome="success",
                    details="Simulated database failure",
                )

    assert rollback_called
    assert "Failed to save audit log: audit_failure_test" in caplog.text
    assert "Simulated audit database failure" in caplog.text


def test_csrf_rejects_post_without_token(client):
    original_csrf_setting = app.config["WTF_CSRF_ENABLED"]

    try:
        app.config["WTF_CSRF_ENABLED"] = True

        response = client.post(
            "/login",
            data={
                "email": "owner@example.com",
                "password": "OwnerTestPass123!",
            },
        )

        assert response.status_code == 400

    finally:
        app.config["WTF_CSRF_ENABLED"] = original_csrf_setting

def test_login_rate_limit_blocks_sixth_attempt(client):
    limiter.enabled = True
    limiter.reset()

    try:
        responses = []

        for _ in range(6):
            response = client.post(
                "/login",
                data={
                    "email": "unknown@example.com",
                    "password": "WrongPassword123!",
                },
                follow_redirects=False,
            )
            responses.append(response.status_code)

        assert responses[:5] != [429] * 5
        assert responses[5] == 429

    finally:
        limiter.enabled = False
        limiter.reset()

def test_upload_rejects_file_over_size_limit(client):
    login(
        client,
        "owner@example.com",
        "OwnerTestPass123!",
    )

    oversized_content = b"A" * (
        app.config["MAX_CONTENT_LENGTH"] + 1
    )

    response = client.post(
        "/documents/upload",
        data={
            "title": "Oversized File",
            "category": "General",
            "file": (
                BytesIO(oversized_content),
                "oversized.txt",
            ),
        },
        content_type="multipart/form-data",
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/dashboard")
    with app.app_context():
        document = Document.query.filter_by(
            original_filename="oversized.txt"
        ).first()

        assert document is None

        event = (
            AuditLog.query
            .filter_by(
                action="document_upload",
                outcome="failure",
            )
            .order_by(AuditLog.id.desc())
            .first()
        )

        assert event is not None
        assert event.actor_id is not None
        assert "size limit" in event.details.lower()
def test_admin_can_view_admin_dashboard(client):
    login(
        client,
        "admin@example.com",
        "AdminTestPass123!",
    )

    response = client.get("/admin")

    assert response.status_code == 200

    page = response.get_data(as_text=True)

    assert "Admin Panel" in page
    assert "Administration overview" in page
    assert "User accounts" in page
    assert "Recent audit activity" in page

    # Verify that the statistics are rendered from database values.
    assert "Total users" in page
    assert "Document owners" in page
    assert "Viewers" in page
    assert "Administrators" in page

