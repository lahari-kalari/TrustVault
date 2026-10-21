
from app import app, db
from models import User

with app.app_context():
    users = db.session.scalars(
        db.select(User)
    ).all()

    if not users:
        print("No users exist in the current database.")
    else:
        print("\nRegistered TrustVault accounts:")
        for user in users:
            print(
                f"Email: {user.email} | "
                f"Active: {user.is_active} | "
                f"Role: {user.role}"
            )
