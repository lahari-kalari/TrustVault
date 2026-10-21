
from app import app, db
from sqlalchemy import inspect, text

with app.app_context():
    inspector = inspect(db.engine)
    tables = inspector.get_table_names()

    print("Database:", app.config["SQLALCHEMY_DATABASE_URI"])
    print("Tables:", tables)

    for table in tables:
        count = db.session.execute(
            text(f'SELECT COUNT(*) FROM "{table}"')
        ).scalar_one()

        print(f"{table}: {count} rows")
