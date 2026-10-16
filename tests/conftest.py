"""Shared pytest fixtures. No test talks to real AWS."""
import pytest

from app import auth, create_app

ENV_VARS = [
    "APP_ENV", "SECRET_KEY", "APP_SECRET_NAME", "AWS_REGION", "DB_SECRET_NAME",
    "RDS_CA_BUNDLE", "S3_BUCKET", "KMS_KEY_ID", "COGNITO_USER_POOL_ID",
    "COGNITO_APP_CLIENT_ID", "AUTH_REQUIRED", "TXN_AMOUNT_LIMIT",
    "TXN_MAX_PER_WINDOW", "TXN_WINDOW_MINUTES",
]


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch):
    """Ignore the developer's own environment and use fake AWS credentials."""
    for name in ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "ap-southeast-2")
    auth._jwks_cache.clear()


@pytest.fixture
def make_app(tmp_path):
    """Build a local-mode app with a throwaway SQLite file and upload folder."""
    def _make(**overrides):
        settings = {
            "APP_ENV": "local",
            "AUTH_REQUIRED": False,
            "SECRET_KEY": "test-secret-key",
            "SQLITE_PATH": str(tmp_path / "test.sqlite"),
            "LOCAL_UPLOAD_DIR": str(tmp_path / "uploads"),
            "CSRF_ENABLED": False,
            "TESTING": True,
        }
        settings.update(overrides)
        return create_app(settings)
    return _make


@pytest.fixture
def client(make_app):
    return make_app().test_client()
