from decimal import Decimal

import pytest
from sqlalchemy import select

from app.db import transactions_table
from app.transactions import (
    APPROVED, HELD_FOR_REVIEW, RULE_AMOUNT_OVER_LIMIT, RULE_FREQUENCY_EXCEEDED,
    evaluate_transaction, parse_amount, parse_recipient,
)

LIMIT = Decimal("5000")
MAX_PER_WINDOW = 5


# --- the pure rule function -------------------------------------------------

def test_normal_amount_is_approved():
    assert evaluate_transaction(Decimal("120.50"), 0, LIMIT, MAX_PER_WINDOW) == (APPROVED, None)


def test_amount_equal_to_limit_is_approved():
    assert evaluate_transaction(Decimal("5000.00"), 0, LIMIT, MAX_PER_WINDOW) == (APPROVED, None)


def test_amount_one_cent_over_limit_is_held():
    assert evaluate_transaction(Decimal("5000.01"), 0, LIMIT, MAX_PER_WINDOW) == (
        HELD_FOR_REVIEW, RULE_AMOUNT_OVER_LIMIT)


def test_one_below_frequency_limit_is_approved():
    assert evaluate_transaction(Decimal("10"), 4, LIMIT, MAX_PER_WINDOW) == (APPROVED, None)


def test_frequency_limit_reached_is_held():
    assert evaluate_transaction(Decimal("10"), 5, LIMIT, MAX_PER_WINDOW) == (
        HELD_FOR_REVIEW, RULE_FREQUENCY_EXCEEDED)


def test_amount_rule_reported_first_when_both_trigger():
    assert evaluate_transaction(Decimal("9999"), 10, LIMIT, MAX_PER_WINDOW) == (
        HELD_FOR_REVIEW, RULE_AMOUNT_OVER_LIMIT)


# --- input validation --------------------------------------------------------

@pytest.mark.parametrize("raw, expected", [("100", "100"), ("0.01", "0.01"), (" 42.5 ", "42.5")])
def test_parse_amount_accepts_valid_values(raw, expected):
    assert parse_amount(raw) == Decimal(expected)


@pytest.mark.parametrize("raw", ["", "0", "0.00", "-5", "1.234", "1e5", "NaN", "1,000", "abc", "12345678901"])
def test_parse_amount_rejects_bad_values(raw):
    with pytest.raises(ValueError):
        parse_amount(raw)


def test_parse_recipient_limits_length():
    assert parse_recipient("  Jane  ") == "Jane"
    with pytest.raises(ValueError):
        parse_recipient("")
    with pytest.raises(ValueError):
        parse_recipient("x" * 101)


# --- the page, end to end (local mode, demo user) -----------------------------

def _all_rows(app):
    with app.extensions["db_engine"].connect() as conn:
        query = select(transactions_table).order_by(transactions_table.c.id)
        return conn.execute(query).mappings().all()


def test_page_holds_large_and_frequent_payments(make_app):
    app = make_app()
    client = app.test_client()

    for _ in range(5):
        client.post("/transactions", data={"amount": "10.00", "recipient": "Alice"})
    client.post("/transactions", data={"amount": "10.00", "recipient": "Alice"})  # 6th in window

    rows = _all_rows(app)

    assert [r["status"] for r in rows] == [APPROVED] * 5 + [HELD_FOR_REVIEW]
    assert rows[-1]["rule_triggered"] == RULE_FREQUENCY_EXCEEDED
    assert rows[0]["amount"] == Decimal("10.00")

    page = client.get("/transactions")
    assert b"FREQUENCY_EXCEEDED" in page.data


def test_page_holds_amount_over_limit(make_app):
    app = make_app()
    client = app.test_client()
    client.post("/transactions", data={"amount": "5000.01", "recipient": "Bob"})
    [row] = _all_rows(app)
    assert (row["status"], row["rule_triggered"]) == (HELD_FOR_REVIEW, RULE_AMOUNT_OVER_LIMIT)


def test_invalid_amount_is_not_stored(make_app):
    app = make_app()
    client = app.test_client()
    client.post("/transactions", data={"amount": "-1", "recipient": "Bob"})
    assert _all_rows(app) == []


def test_post_without_csrf_token_is_rejected(make_app):
    client = make_app(CSRF_ENABLED=True).test_client()
    response = client.post("/transactions", data={"amount": "10", "recipient": "Bob"})
    assert response.status_code == 400
