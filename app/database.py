import os
from collections.abc import Generator

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg://lexledger:lexledger@localhost:5432/lexledger",
)


class Base(DeclarativeBase):
    pass


engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def create_db_and_tables() -> None:
    Base.metadata.create_all(bind=engine)
    run_lightweight_migrations()


def run_lightweight_migrations() -> None:
    with engine.begin() as connection:
        inspector = inspect(connection)
        table_names = set(inspector.get_table_names())

        if "users" in table_names:
            user_columns = {column["name"] for column in inspector.get_columns("users")}
            if "signing_public_key" not in user_columns:
                connection.execute(
                    text("ALTER TABLE users ADD COLUMN signing_public_key VARCHAR(128)")
                )

        if "votes" not in table_names:
            return

        vote_columns = {
            column["name"]: column
            for column in inspector.get_columns("votes")
        }
        missing_vote_columns = {
            "ciphertext_c1": "TEXT",
            "ciphertext_c2": "TEXT",
            "signature": "TEXT",
            "signature_public_key": "VARCHAR(128)",
            "signature_digest": "VARCHAR(64)",
        }
        for column_name, column_type in missing_vote_columns.items():
            if column_name not in vote_columns:
                connection.execute(
                    text(f"ALTER TABLE votes ADD COLUMN {column_name} {column_type}")
                )

        if (
            connection.dialect.name == "postgresql"
            and "choice" in vote_columns
            and not vote_columns["choice"]["nullable"]
        ):
            connection.execute(text("ALTER TABLE votes ALTER COLUMN choice DROP NOT NULL"))

        if connection.dialect.name != "postgresql":
            return

        unique_constraints = inspector.get_unique_constraints("votes")
        has_signature_constraint = any(
            set(constraint.get("column_names", ())) == {"proposal_id", "signature_digest"}
            for constraint in unique_constraints
        )
        if not has_signature_constraint:
            connection.execute(
                text(
                    "ALTER TABLE votes "
                    "ADD CONSTRAINT uq_votes_proposal_signature_digest "
                    "UNIQUE (proposal_id, signature_digest)"
                )
            )


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
