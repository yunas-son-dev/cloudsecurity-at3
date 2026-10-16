# OWNER: Fathima (identity)
"""Identity: Cognito sign-in with TOTP MFA, JWT validation and @require_auth.

Sign-in flow (USER_PASSWORD_AUTH, app client WITHOUT a client secret):
  1. POST /login      -> Cognito initiate_auth(email, password)
  2. Cognito replies with the SOFTWARE_TOKEN_MFA challenge
  3. POST /login/mfa  -> Cognito respond_to_auth_challenge(6-digit code)
  4. Cognito returns ID + access tokens. We validate them, then keep the
     access token in the Flask session (a signed, HttpOnly, Secure cookie).

Every protected page uses @require_auth, which validates the token on EVERY
request: RS256 signature against the user pool's public keys (JWKS), expiry,
issuer, token_use and app client id.
"""
import logging
import re
import time
from functools import wraps

import boto3
import jwt
import requests
from botocore.exceptions import BotoCoreError, ClientError
from flask import (
    Blueprint, current_app, flash, g, jsonify, redirect, render_template,
    request, session, url_for,
)

from .logging_setup import log_security_event

bp = Blueprint("auth", __name__)

# Used for every request when AUTH_REQUIRED=false (local development only).
DEMO_USER_ID = "demo-user"

JWKS_CACHE_SECONDS = 3600  # Cognito rotates keys rarely; refresh hourly
JWKS_MIN_REFRESH_SECONDS = 300  # don't let unknown "kid" values force constant refetches

# issuer URL -> {"keys": {kid: jwk_dict}, "fetched_at": unix_time}
_jwks_cache = {}

MFA_CODE_PATTERN = re.compile(r"[0-9]{6}")


class TokenError(Exception):
    """The token is missing, malformed, expired, wrongly signed or not for us."""


# ---------------------------------------------------------------------------
# JWT validation
# ---------------------------------------------------------------------------

def issuer_url(region, user_pool_id):
    return f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}"


def fetch_jwks(issuer):
    """Download the user pool's public signing keys (isolated so tests can replace it)."""
    response = requests.get(f"{issuer}/.well-known/jwks.json", timeout=5)
    response.raise_for_status()
    return response.json()


def _get_public_key(issuer, kid):
    """Find the public key for this token's "kid", using the cache when we can."""
    now = time.time()
    cached = _jwks_cache.get(issuer)
    expired = cached is None or now - cached["fetched_at"] > JWKS_CACHE_SECONDS
    unknown_kid = (
        cached is not None
        and kid not in cached["keys"]
        and now - cached["fetched_at"] > JWKS_MIN_REFRESH_SECONDS
    )
    if expired or unknown_kid:
        try:
            jwks = fetch_jwks(issuer)
        except requests.RequestException as exc:
            raise TokenError("could not fetch signing keys") from exc
        cached = {"keys": {key["kid"]: key for key in jwks.get("keys", [])}, "fetched_at": now}
        _jwks_cache[issuer] = cached

    jwk = cached["keys"].get(kid)
    if jwk is None:
        raise TokenError("unknown signing key")
    return jwt.PyJWK(jwk).key


def validate_token(token, region, user_pool_id, app_client_id):
    """Validate a Cognito ID or access token and return its claims.

    Raises TokenError for anything that is not a valid token for this app.
    """
    issuer = issuer_url(region, user_pool_id)

    try:
        header = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError as exc:
        raise TokenError("malformed token") from exc

    # Only accept RS256. This blocks "alg: none" and HS256 key-confusion tricks.
    if header.get("alg") != "RS256":
        raise TokenError("unexpected signing algorithm")

    public_key = _get_public_key(issuer, header.get("kid"))

    try:
        claims = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            issuer=issuer,  # checks "iss"
            # "exp" is checked automatically. Cognito access tokens have no
            # "aud" claim, so we check the audience ourselves below.
            options={"require": ["exp", "iss", "sub", "token_use"], "verify_aud": False},
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("token expired") from exc
    except jwt.InvalidTokenError as exc:
        raise TokenError(f"invalid token: {exc}") from exc

    # ID tokens carry the app client id in "aud"; access tokens in "client_id".
    token_use = claims.get("token_use")
    if token_use == "id":
        audience = claims.get("aud")
    elif token_use == "access":
        audience = claims.get("client_id")
    else:
        raise TokenError("unexpected token_use")
    if audience != app_client_id:
        raise TokenError("token was issued to a different app client")

    return claims


def _validate_with_app_config(token):
    cfg = current_app.config
    return validate_token(
        token, cfg["AWS_REGION"], cfg["COGNITO_USER_POOL_ID"], cfg["COGNITO_APP_CLIENT_ID"]
    )


# ---------------------------------------------------------------------------
# @require_auth decorator
# ---------------------------------------------------------------------------

def _token_from_request():
    """Return (token, source). An Authorization header wins over the session."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header:
        scheme, _, value = auth_header.partition(" ")
        if scheme.lower() == "bearer" and value.strip():
            return value.strip(), "header"
        return None, "header"
    return session.get("access_token"), "session"


def _wants_json(source):
    return source == "header" or request.accept_mimetypes.best == "application/json"


def _reject(reason, source):
    """401 JSON for API-style requests, redirect to /login for browsers."""
    # Log the reason only - never the token itself.
    log_security_event("token_rejected", level=logging.WARNING, reason=reason, token_source=source)
    if source == "session":
        session.clear()
    if _wants_json(source):
        response = jsonify(error="unauthorized", reason=reason)
        response.status_code = 401
        response.headers["WWW-Authenticate"] = "Bearer"
        return response
    if reason != "missing token":
        flash("Your session is no longer valid. Please sign in again.", "error")
    return redirect(url_for("auth.login"))


def require_auth(view):
    """Protect a view. Sets g.user_id (Cognito "sub") and g.user_email."""

    @wraps(view)
    def wrapper(*args, **kwargs):
        if not current_app.config["AUTH_REQUIRED"]:
            g.user_id = DEMO_USER_ID
            g.user_email = "demo-user@localhost"
            return view(*args, **kwargs)

        token, source = _token_from_request()
        if not token:
            return _reject("missing token", source)
        try:
            claims = _validate_with_app_config(token)
        except TokenError as exc:
            return _reject(str(exc), source)

        g.user_id = claims["sub"]
        g.user_email = session.get("email") if source == "session" else claims.get("email")
        g.token_claims = claims
        # EXTENSION POINT: role-based access. Cognito puts group membership in
        # claims.get("cognito:groups", []); check it here (e.g. "staff" for a
        # review queue of held transactions) and return 403 if missing.
        # EXTENSION POINT: idle session timeout, e.g. store a "last_seen"
        # timestamp in the session and force a new login after 15 minutes.
        return view(*args, **kwargs)

    return wrapper


# ---------------------------------------------------------------------------
# Cognito API calls (isolated so tests can replace them)
# ---------------------------------------------------------------------------

def _cognito_client():
    # InitiateAuth / RespondToAuthChallenge are public APIs: no IAM permission needed.
    return boto3.client("cognito-idp", region_name=current_app.config["AWS_REGION"])


def cognito_initiate_auth(email, password):
    return _cognito_client().initiate_auth(
        AuthFlow="USER_PASSWORD_AUTH",
        ClientId=current_app.config["COGNITO_APP_CLIENT_ID"],
        AuthParameters={"USERNAME": email, "PASSWORD": password},
    )


def cognito_respond_to_mfa(username, cognito_session, code):
    return _cognito_client().respond_to_auth_challenge(
        ClientId=current_app.config["COGNITO_APP_CLIENT_ID"],
        ChallengeName="SOFTWARE_TOKEN_MFA",
        Session=cognito_session,
        ChallengeResponses={"USERNAME": username, "SOFTWARE_TOKEN_MFA_CODE": code},
    )


# ---------------------------------------------------------------------------
# Routes
# OWNER: Fathima (identity) - login, MFA and logout routes
# ---------------------------------------------------------------------------

@bp.route("/login", methods=["GET", "POST"])
def login():
    if not current_app.config["AUTH_REQUIRED"]:
        # Local stub: no Cognito, everyone is demo-user.
        return render_template("login.html", stub_mode=True)

    if request.method == "GET":
        return render_template("login.html")

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    if not email or not password or len(email) > 254 or len(password) > 256:
        flash("Enter your email and password.", "error")
        return render_template("login.html"), 400

    try:
        result = cognito_initiate_auth(email, password)
    except (ClientError, BotoCoreError) as exc:
        reason = exc.response["Error"]["Code"] if isinstance(exc, ClientError) else "cognito_unavailable"
        log_security_event("login_failure", level=logging.WARNING, email=email, reason=reason)
        # Same message for wrong password / unknown user so we don't reveal which accounts exist.
        flash("Sign-in failed. Check your email and password.", "error")
        return render_template("login.html"), 401

    challenge = result.get("ChallengeName")
    if challenge == "SOFTWARE_TOKEN_MFA":
        # Remember the half-finished sign-in (inside the signed session cookie).
        session.clear()
        session["mfa_pending"] = {
            "email": email,
            "username": result.get("ChallengeParameters", {}).get("USER_ID_FOR_SRP", email),
            "cognito_session": result["Session"],
        }
        log_security_event("mfa_challenge_issued", email=email)
        return redirect(url_for("auth.mfa"))

    if challenge:
        # EXTENSION POINT: handle MFA_SETUP (first-time TOTP enrolment via
        # associate_software_token / verify_software_token) and
        # NEW_PASSWORD_REQUIRED for admin-created users.
        log_security_event("login_failure", level=logging.WARNING, email=email,
                           reason=f"unsupported_challenge:{challenge}")
        flash(f"This account needs a step this demo does not support yet ({challenge}).", "error")
        return render_template("login.html"), 401

    # No challenge = MFA is not enforced on this user pool.
    # EXTENSION POINT: refuse this login instead, so MFA is mandatory in the app too.
    return _complete_login(email, result["AuthenticationResult"], mfa_used=False)


@bp.route("/login/mfa", methods=["GET", "POST"])
def mfa():
    pending = session.get("mfa_pending")
    if not pending:
        return redirect(url_for("auth.login"))

    if request.method == "GET":
        return render_template("mfa.html")

    code = request.form.get("code", "").strip()
    if not MFA_CODE_PATTERN.fullmatch(code):
        flash("Enter the 6-digit code from your authenticator app.", "error")
        return render_template("mfa.html"), 400

    try:
        result = cognito_respond_to_mfa(pending["username"], pending["cognito_session"], code)
    except (ClientError, BotoCoreError) as exc:
        reason = exc.response["Error"]["Code"] if isinstance(exc, ClientError) else "cognito_unavailable"
        log_security_event("login_failure", level=logging.WARNING, email=pending["email"],
                           reason=f"mfa:{reason}")
        # Start again from the password step after a wrong code.
        session.pop("mfa_pending", None)
        flash("That code did not work. Please sign in again.", "error")
        return redirect(url_for("auth.login"))

    return _complete_login(pending["email"], result["AuthenticationResult"], mfa_used=True)


def _complete_login(email, auth_result, mfa_used):
    """Validate the tokens Cognito gave us and start a fresh session."""
    try:
        id_claims = _validate_with_app_config(auth_result["IdToken"])
        _validate_with_app_config(auth_result["AccessToken"])
    except TokenError as exc:
        log_security_event("token_rejected", level=logging.WARNING, reason=str(exc), token_source="login")
        flash("Sign-in failed. Please try again.", "error")
        return redirect(url_for("auth.login"))

    session.clear()  # new session on login prevents session fixation
    session.permanent = True  # expires after PERMANENT_SESSION_LIFETIME (1 hour)
    # Only the access token is kept (cookies are limited to ~4 KB). The refresh
    # token is deliberately not stored: users sign in again when it expires.
    session["access_token"] = auth_result["AccessToken"]
    session["email"] = id_claims.get("email", email)

    log_security_event("login_success", user_id=id_claims["sub"], mfa=mfa_used)
    return redirect(url_for("transactions.index"))


@bp.route("/logout")
def logout():
    # EXTENSION POINT: call Cognito global_sign_out(AccessToken=...) here so
    # the token is revoked server-side, not just forgotten by the browser.
    had_session = "access_token" in session
    session.clear()
    if had_session:
        log_security_event("logout")
    flash("You have been signed out.", "info")
    return redirect(url_for("auth.login"))
