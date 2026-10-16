"""All settings come from environment variables.

On Elastic Beanstalk they are set as "environment properties". Locally they
come from your shell or a `.env` file (see .env.example). Nothing secret is
hard-coded here: secrets are read at startup from AWS Secrets Manager.
"""
import os
from decimal import Decimal, InvalidOperation
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# If any of these are set we assume we are running in AWS.
AWS_MARKER_VARIABLES = ("DB_SECRET_NAME", "S3_BUCKET", "COGNITO_USER_POOL_ID")


class ConfigError(RuntimeError):
    """Raised when the settings are missing or invalid. Stops the app from starting."""


def _as_bool(value, default):
    if value is None or value == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def load_settings(environ=None):
    """Read every setting from the environment and return a plain dict."""
    env = os.environ if environ is None else environ

    app_env = env.get("APP_ENV") or (
        "aws" if any(env.get(name) for name in AWS_MARKER_VARIABLES) else "local"
    )

    try:
        settings = {
            # "local" = SQLite + local disk uploads, "aws" = RDS + S3 + Secrets Manager.
            "APP_ENV": app_env,
            "SECRET_KEY": env.get("SECRET_KEY") or None,
            "APP_SECRET_NAME": env.get("APP_SECRET_NAME") or None,
            "AWS_REGION": env.get("AWS_REGION") or "ap-southeast-2",
            "DB_SECRET_NAME": env.get("DB_SECRET_NAME") or None,
            "RDS_CA_BUNDLE": env.get("RDS_CA_BUNDLE") or None,
            "S3_BUCKET": env.get("S3_BUCKET") or None,
            "KMS_KEY_ID": env.get("KMS_KEY_ID") or None,
            "COGNITO_USER_POOL_ID": env.get("COGNITO_USER_POOL_ID") or None,
            "COGNITO_APP_CLIENT_ID": env.get("COGNITO_APP_CLIENT_ID") or None,
            # Secure default: authentication is ON in AWS. It is only off by
            # default in local mode so `flask run` works with no Cognito.
            "AUTH_REQUIRED": _as_bool(env.get("AUTH_REQUIRED"), default=(app_env == "aws")),
            # Transaction rule thresholds (see transactions.py).
            "TXN_AMOUNT_LIMIT": Decimal(env.get("TXN_AMOUNT_LIMIT") or "5000"),
            "TXN_MAX_PER_WINDOW": int(env.get("TXN_MAX_PER_WINDOW") or "5"),
            "TXN_WINDOW_MINUTES": int(env.get("TXN_WINDOW_MINUTES") or "10"),
            # Local-mode only. Not environment variables; tests override them.
            "SQLITE_PATH": str(PROJECT_ROOT / "namawin-local.sqlite"),
            "LOCAL_UPLOAD_DIR": str(PROJECT_ROOT / "local_uploads"),
            "CSRF_ENABLED": True,
        }
    except (InvalidOperation, ValueError) as exc:
        raise ConfigError(f"A TXN_* setting is not a valid number: {exc}") from exc

    return settings


def validate_settings(settings):
    """Fail fast at startup with a clear message instead of failing later."""
    problems = []

    if settings["APP_ENV"] not in ("local", "aws"):
        problems.append("APP_ENV must be 'local' or 'aws'.")

    if settings["APP_ENV"] == "aws":
        if not settings["DB_SECRET_NAME"]:
            problems.append("DB_SECRET_NAME is required when APP_ENV=aws.")
        if not settings["RDS_CA_BUNDLE"]:
            problems.append("RDS_CA_BUNDLE is required when APP_ENV=aws (TLS to RDS is mandatory).")

    if settings["AUTH_REQUIRED"]:
        if not settings["COGNITO_USER_POOL_ID"] or not settings["COGNITO_APP_CLIENT_ID"]:
            problems.append(
                "AUTH_REQUIRED=true needs COGNITO_USER_POOL_ID and COGNITO_APP_CLIENT_ID."
            )

    if settings["TXN_AMOUNT_LIMIT"] <= 0:
        problems.append("TXN_AMOUNT_LIMIT must be greater than 0.")
    if settings["TXN_MAX_PER_WINDOW"] < 1 or settings["TXN_WINDOW_MINUTES"] < 1:
        problems.append("TXN_MAX_PER_WINDOW and TXN_WINDOW_MINUTES must be at least 1.")

    if problems:
        raise ConfigError("Invalid configuration: " + " ".join(problems))
