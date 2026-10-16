# OWNER: Ashwin (data and application security)
"""Database engine, table definitions, schema creation and seed data.

Local mode: a SQLite file, no AWS needed.
AWS mode:   Amazon RDS for MySQL via PyMySQL, credentials from Secrets
            Manager, and TLS is REQUIRED (the server certificate is verified
            against the AWS RDS CA bundle and the hostname is checked).
"""
from datetime import datetime, timezone

from flask import current_app
from sqlalchemy import (
    Column, DateTime, Integer, MetaData, Numeric, String, Table, Text,
    create_engine, func, insert, select,
)
from sqlalchemy.engine import URL

from .secrets import load_db_credentials

metadata = MetaData()

transactions_table = Table(
    "transactions",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("user_id", String(128), nullable=False, index=True),  # Cognito "sub"
    Column("amount", Numeric(12, 2), nullable=False),  # exact decimal, never float
    Column("recipient", String(100), nullable=False),
    Column("status", String(20), nullable=False),  # APPROVED or HELD_FOR_REVIEW
    Column("rule_triggered", String(40), nullable=True),
    Column("created_at", DateTime, nullable=False, index=True),  # UTC
)

articles_table = Table(
    "articles",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("title", String(200), nullable=False),
    Column("body", Text, nullable=False),
)

SAMPLE_ARTICLES = [
    ("How to set up MFA", "Protect your account with an authenticator app. Go to Security settings and scan the QR code."),
    ("Transfer limits explained", "Transfers over your daily limit are held for review by our fraud team."),
    ("Why was my payment held?", "Payments can be held when the amount is unusually large or you make many payments quickly."),
    ("Uploading identity documents", "You can upload PDF, PNG, JPG or TXT files up to 5 MB. Files are encrypted at rest."),
    ("Spotting phishing messages", "Namawin will never ask for your password or MFA code by email, SMS or phone."),
    ("Changing your password", "Use a long, unique passphrase. You will be asked for your MFA code after changing it."),
    ("Scheduled payments", "Set up recurring payments to pay bills automatically on a chosen date."),
    ("Contacting support", "Reach our support team 24/7 through the secure message centre in the app."),
]


def utcnow():
    """Current UTC time without tzinfo (portable across SQLite and MySQL DATETIME)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def build_engine(config):
    """Create the SQLAlchemy engine for the current mode."""
    if config["APP_ENV"] == "local":
        return create_engine(f"sqlite:///{config['SQLITE_PATH']}")

    creds = load_db_credentials(config["DB_SECRET_NAME"], config["AWS_REGION"])
    url = URL.create(
        "mysql+pymysql",
        username=creds["username"],
        password=creds["password"],  # stays in memory; SQLAlchemy masks it in repr/logs
        host=creds["host"],
        port=creds["port"],
        database=creds["dbname"],
    )
    return create_engine(
        url,
        # Require TLS: verify the RDS certificate against the AWS CA bundle and
        # check that the certificate matches the hostname.
        connect_args={"ssl": {"ca": config["RDS_CA_BUNDLE"], "check_hostname": True}},
        pool_pre_ping=True,  # drop dead connections (e.g. after an RDS failover)
        pool_recycle=300,
    )


def init_db(app):
    """Create the engine, create tables if missing, and seed sample articles."""
    engine = build_engine(app.config)
    metadata.create_all(engine)  # only creates tables that do not exist yet
    _seed_articles(engine)
    app.extensions["db_engine"] = engine


def get_engine():
    return current_app.extensions["db_engine"]


def _seed_articles(engine):
    with engine.begin() as conn:
        count = conn.execute(select(func.count()).select_from(articles_table)).scalar_one()
        if count == 0:
            conn.execute(
                insert(articles_table),
                [{"title": title, "body": body} for title, body in SAMPLE_ARTICLES],
            )
