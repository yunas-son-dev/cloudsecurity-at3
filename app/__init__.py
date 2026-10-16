"""Application factory for the Namawin demo bank.

create_app() wires together: settings, logging, the database, the
blueprints (pages) and a few app-wide security controls:
  * ProxyFix so Flask trusts the ALB's X-Forwarded-* headers
  * secure session cookie flags
  * security response headers
  * a simple CSRF token check on HTML form posts
"""
import hmac
import logging
import os
from datetime import timedelta

from flask import Flask, abort, flash, redirect, request, session, url_for
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.middleware.proxy_fix import ProxyFix

from .config import ConfigError, load_settings, validate_settings
from .logging_setup import configure_logging, log_security_event
from .secrets import load_app_secret_key

log = logging.getLogger(__name__)

# Only our own CSS, no inline scripts/styles, no framing by other sites.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
    "form-action 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none'"
)

# 5 MB file limit (documents.py) plus a little room for the multipart form itself.
MAX_REQUEST_BYTES = 5 * 1024 * 1024 + 64 * 1024


def create_app(overrides=None):
    configure_logging()

    settings = load_settings()
    if overrides:
        settings.update(overrides)  # used by tests
    validate_settings(settings)

    app = Flask(__name__)
    app.config.update(settings)
    app.config.update(
        SECRET_KEY=_resolve_secret_key(settings),
        SESSION_COOKIE_HTTPONLY=True,  # JavaScript cannot read the session cookie
        # Secure = cookie only sent over HTTPS. Off in local mode because
        # `flask run` serves plain http://127.0.0.1.
        SESSION_COOKIE_SECURE=settings["APP_ENV"] == "aws",
        SESSION_COOKIE_SAMESITE="Lax",  # not sent on cross-site POSTs
        PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
        MAX_CONTENT_LENGTH=MAX_REQUEST_BYTES,
    )

    # Request path on AWS: client -> ALB -> nginx (on the instance) -> gunicorn.
    # The ALB adds the client IP to X-Forwarded-For, and nginx adds the ALB's IP,
    # so the real client is the 2nd value from the right (x_for=2).
    # The ALB sets X-Forwarded-Proto/Port because it terminates HTTPS.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=2, x_proto=1, x_port=1)

    from .db import init_db
    init_db(app)

    from . import auth, documents, health, search, transactions
    app.register_blueprint(health.bp)
    app.register_blueprint(auth.bp)
    app.register_blueprint(transactions.bp)
    app.register_blueprint(documents.bp)
    app.register_blueprint(search.bp)

    _register_security_hooks(app)

    @app.route("/")
    def home():
        return redirect(url_for("transactions.index"))

    if not app.config["AUTH_REQUIRED"]:
        log.warning(
            "!!! AUTH_REQUIRED=false - AUTHENTICATION IS DISABLED. Every request acts as "
            "'demo-user'. Use this only for local development or the first deployment "
            "before Cognito exists. !!!"
        )
    log.info(
        "Namawin app started",
        extra={"fields": {"app_env": app.config["APP_ENV"], "auth_required": app.config["AUTH_REQUIRED"]}},
    )
    return app


def _resolve_secret_key(settings):
    """Flask SECRET_KEY signs the session cookie, so it must stay secret."""
    if settings["APP_SECRET_NAME"]:
        return load_app_secret_key(settings["APP_SECRET_NAME"], settings["AWS_REGION"])
    if settings["SECRET_KEY"]:
        return settings["SECRET_KEY"]
    if settings["APP_ENV"] == "local":
        log.warning("SECRET_KEY not set - using a random key. Sessions reset when the app restarts.")
        return os.urandom(32).hex()
    raise ConfigError("Set APP_SECRET_NAME (preferred) or SECRET_KEY when APP_ENV=aws.")


def _csrf_token():
    """Return this session's CSRF token, creating one if needed."""
    if "csrf_token" not in session:
        session["csrf_token"] = os.urandom(32).hex()
    return session["csrf_token"]


def _register_security_hooks(app):
    @app.context_processor
    def template_helpers():
        return {"csrf_token": _csrf_token, "auth_required": app.config["AUTH_REQUIRED"]}

    @app.before_request
    def check_csrf_token():
        if request.method != "POST" or not app.config["CSRF_ENABLED"]:
            return
        # Bearer-token API calls do not use the session cookie, so a malicious
        # site cannot forge them (browsers will not add that header cross-site).
        if request.headers.get("Authorization"):
            return
        sent = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not expected or not hmac.compare_digest(sent.encode(), expected.encode()):
            log_security_event("csrf_rejected", level=logging.WARNING)
            abort(400, description="Missing or invalid CSRF token.")

    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
        if request.is_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        if not request.path.startswith("/static/"):
            # Pages show account data, so browsers and proxies must not cache them.
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(RequestEntityTooLarge)
    def request_too_large(_error):
        flash("That file is too large. The limit is 5 MB.", "error")
        return redirect(url_for("documents.index"))
