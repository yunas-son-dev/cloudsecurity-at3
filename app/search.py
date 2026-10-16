# OWNER: Ashwin (data and application security)
"""Public help-article search.

This page is the target for the AWS WAF SQL injection demo. The WAF should
block obvious attacks before they reach us, but the code is safe on its own
too: the user's text is only ever passed as a BOUND PARAMETER (:pattern), so
the database treats it as data, never as SQL. Never build SQL with f-strings,
% formatting or string concatenation.
"""
from flask import Blueprint, render_template, request
from sqlalchemy import text

from .db import get_engine
from .logging_setup import log_security_event

bp = Blueprint("search", __name__)

MAX_QUERY_LENGTH = 100

# :pattern is a placeholder. The driver sends its value separately from the SQL.
SEARCH_SQL = text(
    "SELECT id, title, body FROM articles "
    "WHERE title LIKE :pattern OR body LIKE :pattern "
    "ORDER BY id LIMIT 20"
)


def search_articles(engine, query):
    # This builds the VALUE for :pattern (e.g. "%MFA%"), not SQL text.
    pattern = f"%{query}%"
    with engine.connect() as conn:
        return conn.execute(SEARCH_SQL, {"pattern": pattern}).mappings().all()


@bp.route("/search")
def index():
    query = request.args.get("q", "").strip()[:MAX_QUERY_LENGTH]
    results = search_articles(get_engine(), query) if query else []

    if query:
        # Log the length and result count, not the raw text (it may contain attack payloads).
        # EXTENSION POINT: log a hash of the query, or flag suspicious patterns
        # here so app logs can be correlated with AWS WAF logs.
        log_security_event("search", query_length=len(query), result_count=len(results))

    return render_template("search.html", query=query, results=results)
