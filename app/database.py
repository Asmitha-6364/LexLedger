import os
import logging
from collections.abc import Generator
from urllib.parse import quote_plus

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


logger = logging.getLogger("lexledger.database")


def build_database_url() -> str:
    direct_url = os.getenv("DATABASE_URL")
    if direct_url:
        return direct_url

    user = os.getenv("POSTGRES_USER", "lexledger")
    password = os.getenv("POSTGRES_PASSWORD")
    host = os.getenv("POSTGRES_HOST", "localhost")
    port = os.getenv("POSTGRES_PORT", "5432")
    database = os.getenv("POSTGRES_DB", "lexledger")

    if password is None:
        password = "lexledger"
        logger.warning(
            "POSTGRES_PASSWORD is not set; using insecure local-development database credentials."
        )

    return (
        "postgresql+psycopg://"
        f"{quote_plus(user)}:{quote_plus(password)}@{host}:{port}/{quote_plus(database)}"
    )


DATABASE_URL = build_database_url()


class Base(DeclarativeBase):
    pass


engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def create_db_and_tables() -> None:
    if engine.dialect.name == "postgresql":
        with engine.begin() as connection:
            connection.execute(text("CREATE EXTENSION IF NOT EXISTS vector;"))

    Base.metadata.create_all(bind=engine)

    # Database-agnostic table creation for clause_embeddings
    with engine.begin() as connection:
        inspector = inspect(connection)
        table_names = set(inspector.get_table_names())
        if "clause_embeddings" not in table_names:
            if connection.dialect.name == "postgresql":
                connection.execute(text("""
                    CREATE TABLE clause_embeddings (
                        id SERIAL PRIMARY KEY,
                        clause_id INTEGER NOT NULL REFERENCES clauses(id) ON DELETE CASCADE,
                        embedding VECTOR(1536) NOT NULL
                    )
                """))
            else:
                connection.execute(text("""
                    CREATE TABLE clause_embeddings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        clause_id INTEGER NOT NULL REFERENCES clauses(id) ON DELETE CASCADE,
                        embedding TEXT NOT NULL
                    )
                """))

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
            if "organization_id" not in user_columns:
                connection.execute(
                    text("ALTER TABLE users ADD COLUMN organization_id INTEGER REFERENCES organizations(id) ON DELETE SET NULL")
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
