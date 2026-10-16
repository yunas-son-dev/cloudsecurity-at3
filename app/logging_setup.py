"""JSON-style structured logging to stdout.

Elastic Beanstalk ships stdout to CloudWatch Logs, where one JSON object per
line is easy to search and filter (for example `{ $.event = "login_failure" }`).

RULE: never log passwords, tokens, secrets or database credentials.
"""
import json
import logging
import sys
from datetime import datetime, timezone

from flask import has_request_context, request


class JsonFormatter(logging.Formatter):
    """Formats every log record as a single JSON line."""

    def format(self, record):
        entry = {
            "time": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Extra key/value pairs passed by log_security_event().
        entry.update(getattr(record, "fields", {}))
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


def configure_logging(level=logging.INFO):
    """Send all application logs to stdout as JSON (safe to call twice)."""
    root = logging.getLogger()
    already_configured = any(isinstance(h.formatter, JsonFormatter) for h in root.handlers)
    if not already_configured:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonFormatter())
        root.addHandler(handler)
    root.setLevel(level)
    # boto3/botocore are chatty at INFO; we only want their warnings.
    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("boto3").setLevel(logging.WARNING)


security_log = logging.getLogger("namawin.security")


def log_security_event(event, level=logging.INFO, **fields):
    """Log a security-relevant event such as login_failure or transaction_held.

    Callers pass plain facts (user_id, reason, rule ...). Never pass a
    password, token, secret or credential here.
    """
    fields["event"] = event
    if has_request_context():
        fields.setdefault("source_ip", request.remote_addr)  # real client IP thanks to ProxyFix
        fields.setdefault("path", request.path)
    security_log.log(level, event, extra={"fields": fields})
