"""JWT validation tests using a locally generated RSA key and a fake JWKS.

Nothing here calls AWS: fetch_jwks and the Cognito calls are replaced.
"""
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from app import auth

REGION = "ap-southeast-2"
POOL_ID = "ap-southeast-2_TestPool"
CLIENT_ID = "test-app-client-id"
ISSUER = f"https://cognito-idp.{REGION}.amazonaws.com/{POOL_ID}"
KID = "test-key-1"


@pytest.fixture(scope="module")
def signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def attacker_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def auth_app(make_app, signing_key, monkeypatch):
    jwk = RSAAlgorithm.to_jwk(signing_key.public_key(), as_dict=True)
    jwk.update({"kid": KID, "alg": "RS256", "use": "sig"})
    monkeypatch.setattr(auth, "fetch_jwks", lambda issuer: {"keys": [jwk]})
    return make_app(
        AUTH_REQUIRED=True, AWS_REGION=REGION,
        COGNITO_USER_POOL_ID=POOL_ID, COGNITO_APP_CLIENT_ID=CLIENT_ID,
    )


def make_token(key, kid=KID, **overrides):
    now = int(time.time())
    claims = {
        "sub": "user-123", "iss": ISSUER, "token_use": "access", "client_id": CLIENT_ID,
        "iat": now, "exp": now + 3600,
    }
    claims.update(overrides)
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": kid})


def get_with_token(app, token):
    return app.test_client().get("/transactions", headers={"Authorization": f"Bearer {token}"})


# --- accepted ---------------------------------------------------------------

def test_valid_access_token_is_accepted(auth_app, signing_key):
    assert get_with_token(auth_app, make_token(signing_key)).status_code == 200


def test_valid_id_token_is_accepted(auth_app, signing_key):
    token = make_token(signing_key, token_use="id", aud=CLIENT_ID, client_id=None, email="a@example.com")
    assert get_with_token(auth_app, token).status_code == 200


def test_valid_token_in_session_is_accepted(auth_app, signing_key):
    client = auth_app.test_client()
    with client.session_transaction() as sess:
        sess["access_token"] = make_token(signing_key)
    assert client.get("/transactions").status_code == 200


# --- rejected ---------------------------------------------------------------

def assert_rejected(response, reason_fragment):
    assert response.status_code == 401
    assert response.is_json
    assert reason_fragment in response.get_json()["reason"]


def test_expired_token_is_rejected(auth_app, signing_key):
    token = make_token(signing_key, exp=int(time.time()) - 60)
    assert_rejected(get_with_token(auth_app, token), "expired")


def test_bad_signature_is_rejected(auth_app, attacker_key):
    # Signed by a different key but claiming the real key id.
    assert_rejected(get_with_token(auth_app, make_token(attacker_key)), "invalid token")


def test_wrong_issuer_is_rejected(auth_app, signing_key):
    token = make_token(signing_key, iss="https://cognito-idp.us-east-1.amazonaws.com/other")
    assert_rejected(get_with_token(auth_app, token), "invalid token")


def test_wrong_app_client_is_rejected(auth_app, signing_key):
    token = make_token(signing_key, client_id="some-other-client")
    assert_rejected(get_with_token(auth_app, token), "different app client")


def test_wrong_token_use_is_rejected(auth_app, signing_key):
    token = make_token(signing_key, token_use="refresh")
    assert_rejected(get_with_token(auth_app, token), "token_use")


def test_unknown_key_id_is_rejected(auth_app, signing_key):
    assert_rejected(get_with_token(auth_app, make_token(signing_key, kid="nope")), "unknown signing key")


def test_alg_none_token_is_rejected(auth_app):
    token = jwt.encode({"sub": "x", "iss": ISSUER}, None, algorithm="none", headers={"kid": KID})
    assert_rejected(get_with_token(auth_app, token), "algorithm")


def test_malformed_token_is_rejected(auth_app):
    assert_rejected(get_with_token(auth_app, "not-a-jwt"), "malformed")


def test_missing_token_api_request_gets_401_json(auth_app):
    response = auth_app.test_client().get("/transactions", headers={"Accept": "application/json"})
    assert_rejected(response, "missing token")


def test_missing_token_browser_request_redirects_to_login(auth_app):
    response = auth_app.test_client().get("/transactions", headers={"Accept": "text/html"})
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")


def test_jwks_is_cached(auth_app, signing_key, monkeypatch):
    calls = []
    real_fetch = auth.fetch_jwks
    monkeypatch.setattr(auth, "fetch_jwks", lambda issuer: calls.append(issuer) or real_fetch(issuer))
    for _ in range(3):
        get_with_token(auth_app, make_token(signing_key))
    assert len(calls) == 1


# --- login + MFA flow with Cognito mocked -------------------------------------

def test_login_with_mfa_sets_session(auth_app, signing_key, monkeypatch):
    monkeypatch.setattr(auth, "cognito_initiate_auth", lambda email, password: {
        "ChallengeName": "SOFTWARE_TOKEN_MFA",
        "Session": "opaque-cognito-session",
        "ChallengeParameters": {"USER_ID_FOR_SRP": "user-123"},
    })
    seen = {}

    def fake_respond(username, cognito_session, code):
        seen.update(username=username, session=cognito_session, code=code)
        return {"AuthenticationResult": {
            "AccessToken": make_token(signing_key),
            "IdToken": make_token(signing_key, token_use="id", aud=CLIENT_ID, email="a@example.com"),
        }}
    monkeypatch.setattr(auth, "cognito_respond_to_mfa", fake_respond)

    client = auth_app.test_client()
    step1 = client.post("/login", data={"email": "A@example.com", "password": "pw"})
    assert step1.headers["Location"].endswith("/login/mfa")

    step2 = client.post("/login/mfa", data={"code": "123456"})
    assert step2.headers["Location"].endswith("/transactions")
    assert seen == {"username": "user-123", "session": "opaque-cognito-session", "code": "123456"}

    with client.session_transaction() as sess:
        assert sess["email"] == "a@example.com"
        assert "mfa_pending" not in sess
    assert client.get("/transactions").status_code == 200


def test_mfa_code_must_be_six_digits(auth_app):
    client = auth_app.test_client()
    with client.session_transaction() as sess:
        sess["mfa_pending"] = {"email": "a@example.com", "username": "u", "cognito_session": "s"}
    assert client.post("/login/mfa", data={"code": "12ab56"}).status_code == 400
