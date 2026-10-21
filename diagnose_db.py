
from app import app, db
from sqlalchemy import inspect, text

with app.app_context():
    print("\n=== DATABASE DIAGNOSTIC ===")
    print("Database URI:", app.config["SQLALCHEMY_DATABASE_URI"])

    inspector = inspect(db.engine)
    tables = inspector.get_table_names()

    print("\nTables:", tables)

    for table in tables:
        print(f"\n--- {table} ---")

        rows = db.session.execute(
            text(f'SELECT * FROM "{table}" LIMIT 10')
        ).mappings().all()

        count = db.session.execute(
            text(f'SELECT COUNT(*) FROM "{table}"')
        ).scalar_one()

        print("Total rows:", count)

        for row in rows:
            # Do not print password hashes or other sensitive fields.
            safe_row = {
                key: (
                    "[HIDDEN]"
                    if any(word in key.lower()
                for word in ["password", "secret", "token"])
                    else value
                )
                for key, value in row.items()
            }
            print(dict(safe_row))

    print("\n=== END DIAGNOSTIC ===")
