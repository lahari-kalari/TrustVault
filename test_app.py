
import os

import pytest
from werkzeug.security import generate_password_hash

from app import app, db
from models import User, Document, Permission


@pytest.fixture
def client():
    app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
        SECRET_KEY="test-secret-key",
        SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
        UPLOAD_FOLDER="test_private_uploads",
    )

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

        db.session.add_all([owner, viewer])
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
