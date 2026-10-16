# OWNER: Ashwin (data and application security)
"""Transactions page and the rule-based fraud checks.

The rules live in ONE pure function, evaluate_transaction(), so they are
easy to unit test and explain. The view just gathers the inputs (amount and
how many recent transactions the user has) and stores the result.
"""
import re
from datetime import timedelta
from decimal import Decimal

from flask import Blueprint, current_app, flash, g, redirect, render_template, request, url_for
from sqlalchemy import func, insert, select

from .auth import require_auth
from .db import get_engine, transactions_table, utcnow
from .logging_setup import log_security_event

bp = Blueprint("transactions", __name__)

APPROVED = "APPROVED"
HELD_FOR_REVIEW = "HELD_FOR_REVIEW"
RULE_AMOUNT_OVER_LIMIT = "AMOUNT_OVER_LIMIT"
RULE_FREQUENCY_EXCEEDED = "FREQUENCY_EXCEEDED"

# Digits, optional dot and at most 2 decimals. No signs, commas or exponents.
AMOUNT_PATTERN = re.compile(r"[0-9]{1,10}(\.[0-9]{1,2})?")
MAX_RECIPIENT_LENGTH = 100


def evaluate_transaction(amount, recent_count, amount_limit, max_per_window):
    """Decide whether a transaction is approved or held for review.

    amount          -- Decimal amount of the new transaction
    recent_count    -- how many transactions the user already made in the time window
    amount_limit    -- Decimal; amounts ABOVE this are held (equal is fine)
    max_per_window  -- if the user ALREADY has this many recent transactions, hold

    Returns (status, rule_triggered). rule_triggered is None when approved.
    """
    # Rule 1: unusually large payment.
    if amount > amount_limit:
        return HELD_FOR_REVIEW, RULE_AMOUNT_OVER_LIMIT

    # Rule 2: too many payments in a short time (velocity check).
    if recent_count >= max_per_window:
        return HELD_FOR_REVIEW, RULE_FREQUENCY_EXCEEDED

    # EXTENSION POINT: add more rules here, e.g. first payment to a new
    # recipient, payments at unusual hours, or a daily total limit.
    return APPROVED, None


def parse_amount(raw):
    """Turn form input into a positive Decimal with at most 2 decimal places."""
    raw = (raw or "").strip()
    if not AMOUNT_PATTERN.fullmatch(raw):
        raise ValueError("Amount must be a number with at most 2 decimal places, e.g. 125.50.")
    amount = Decimal(raw)
    if amount <= 0:
        raise ValueError("Amount must be greater than zero.")
    return amount


def parse_recipient(raw):
    recipient = (raw or "").strip()
    if not recipient or len(recipient) > MAX_RECIPIENT_LENGTH or not recipient.isprintable():
        raise ValueError(f"Recipient must be 1 to {MAX_RECIPIENT_LENGTH} printable characters.")
    return recipient


def count_recent_transactions(conn, user_id, since):
    query = (
        select(func.count())
        .select_from(transactions_table)
        .where(transactions_table.c.user_id == user_id)
        .where(transactions_table.c.created_at >= since)
    )
    return conn.execute(query).scalar_one()


@bp.route("/transactions", methods=["GET", "POST"])
@require_auth
def index():
    cfg = current_app.config
    engine = get_engine()

    if request.method == "POST":
        try:
            amount = parse_amount(request.form.get("amount"))
            recipient = parse_recipient(request.form.get("recipient"))
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("transactions.index"))

        now = utcnow()
        window_start = now - timedelta(minutes=cfg["TXN_WINDOW_MINUTES"])

        with engine.begin() as conn:
            # Every attempt counts towards the velocity rule, held ones included.
            recent_count = count_recent_transactions(conn, g.user_id, window_start)
            status, rule = evaluate_transaction(
                amount, recent_count, cfg["TXN_AMOUNT_LIMIT"], cfg["TXN_MAX_PER_WINDOW"]
            )
            conn.execute(
                insert(transactions_table).values(
                    user_id=g.user_id, amount=amount, recipient=recipient,
                    status=status, rule_triggered=rule, created_at=now,
                )
            )

        if status == HELD_FOR_REVIEW:
            log_security_event("transaction_held", user_id=g.user_id, rule=rule, amount=str(amount))
            flash(f"Payment of ${amount} is held for review ({rule}).", "warning")
        else:
            log_security_event("transaction_approved", user_id=g.user_id, amount=str(amount))
            flash(f"Payment of ${amount} approved.", "success")
        # Redirect after POST so refreshing the page does not resubmit the payment.
        return redirect(url_for("transactions.index"))

    with engine.connect() as conn:
        rows = conn.execute(
            select(transactions_table)
            .where(transactions_table.c.user_id == g.user_id)  # users only see their own rows
            .order_by(transactions_table.c.created_at.desc(), transactions_table.c.id.desc())
            .limit(50)
        ).mappings().all()

    return render_template(
        "transactions.html",
        rows=rows,
        amount_limit=cfg["TXN_AMOUNT_LIMIT"],
        max_per_window=cfg["TXN_MAX_PER_WINDOW"],
        window_minutes=cfg["TXN_WINDOW_MINUTES"],
    )
