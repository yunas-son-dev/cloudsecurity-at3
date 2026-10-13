import pytest

from app.search import search_articles


def test_normal_query_returns_results(client):
    response = client.get("/search", query_string={"q": "MFA"})
    assert response.status_code == 200
    assert b"How to set up MFA" in response.data


@pytest.mark.parametrize("payload", [
    "' OR '1'='1",
    "' OR 1=1 --",
    "x'; DROP TABLE articles; --",
    "' UNION SELECT 1, 2, 3 --",
])
def test_sql_injection_is_treated_as_plain_text(make_app, payload):
    app = make_app()
    client = app.test_client()

    response = client.get("/search", query_string={"q": payload})
    assert response.status_code == 200  # never a database error
    assert b"No results." in response.data

    # The payload only matched as a literal string, so nothing came back,
    # and the table still exists with all its rows.
    engine = app.extensions["db_engine"]
    assert search_articles(engine, payload) == []
    assert len(search_articles(engine, "")) == 8


def test_query_is_html_escaped(client):
    response = client.get("/search", query_string={"q": "<script>alert(1)</script>"})
    assert b"<script>alert(1)</script>" not in response.data
    assert b"&lt;script&gt;" in response.data
