"""Health check used by the ALB / Elastic Beanstalk."""
from flask import Blueprint

bp = Blueprint("health", __name__)


@bp.route("/health")
def health():
    # Deliberately does NOT touch the database: a short RDS blip should not
    # make the ALB mark every instance unhealthy and replace them.
    return "ok", 200, {"Content-Type": "text/plain"}
