# OWNER: Ashwin (data and application security)
"""Read secrets from AWS Secrets Manager.

Credentials are only ever held in memory. They are never hard-coded,
logged or written to disk. The EC2 instance profile must allow
`secretsmanager:GetSecretValue` on these secrets (plus `kms:Decrypt` if the
secret uses a customer-managed KMS key).
"""
import json

import boto3

# Keys we need from the standard "Credentials for Amazon RDS database" secret.
REQUIRED_DB_KEYS = ("username", "password", "host")


def get_secret_string(secret_name, region):
    """The ONLY function that calls Secrets Manager (tests mock this or use moto)."""
    client = boto3.client("secretsmanager", region_name=region)
    response = client.get_secret_value(SecretId=secret_name)
    return response["SecretString"]


def load_db_credentials(secret_name, region):
    """Return the RDS connection details from the standard RDS secret JSON.

    Expected JSON: {"username", "password", "host", "port", "dbname", ...}
    """
    data = json.loads(get_secret_string(secret_name, region))

    missing = [key for key in REQUIRED_DB_KEYS if not data.get(key)]
    if missing:
        # Only report key NAMES, never values.
        raise RuntimeError(f"Database secret '{secret_name}' is missing keys: {', '.join(missing)}")

    # EXTENSION POINT: support secret rotation by re-reading the secret and
    # rebuilding the engine when MySQL rejects the old password.
    return {
        "username": data["username"],
        "password": data["password"],
        "host": data["host"],
        "port": int(data.get("port") or 3306),
        "dbname": data.get("dbname") or "namawin",
    }


def load_app_secret_key(secret_name, region):
    """Return the Flask SECRET_KEY stored in Secrets Manager.

    The secret may be plain text, or JSON like {"SECRET_KEY": "..."}.
    """
    raw = get_secret_string(secret_name, region)
    try:
        data = json.loads(raw)
    except ValueError:
        return raw  # plain-text secret
    if isinstance(data, dict) and data.get("SECRET_KEY"):
        return data["SECRET_KEY"]
    raise RuntimeError(f"Secret '{secret_name}' must be plain text or JSON with a SECRET_KEY field.")
