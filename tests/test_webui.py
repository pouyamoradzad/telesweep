"""Tests for the web UI: auth, scan cache, dry-run preview, and deletion."""

from __future__ import annotations

import pytest

from telesweep.actions import ActionExecutor
from telesweep.rules import evaluate_all
from telesweep.webui import create_app

from .conftest import days_ago, make_meta


class FakeWrapper:
    def __init__(self):
        self.client = None

    async def safe_request(self, fn, *args, **kwargs):
        return None


@pytest.fixture
def app(config):
    wrapper = FakeWrapper()
    executor = ActionExecutor(wrapper, config, dry_run=True)
    return create_app(wrapper, config, None, executor)


@pytest.fixture
def client(app):
    from fastapi.testclient import TestClient

    return TestClient(app)


@pytest.fixture
def populated_app(config):
    metas = evaluate_all(
        [
            make_meta(id=7770000, name="Saved Messages", message_count=5),
            make_meta(
                id=100,
                name="Spam Bot",
                entity_type="bot",
                is_bot=True,
                is_scam=True,
                last_message_date=days_ago(400),
                message_count=1,
            ),
        ],
        config,
    )
    wrapper = FakeWrapper()
    executor = ActionExecutor(wrapper, config, dry_run=True)
    app = create_app(wrapper, config, None, executor)
    app.state.shared_state.metas = metas
    return app


@pytest.fixture
def populated_client(populated_app):
    from fastapi.testclient import TestClient

    return TestClient(populated_app)


class TestAuth:
    def test_missing_token_is_rejected(self, client):
        assert client.get("/api/chats").status_code == 401

    def test_wrong_token_is_rejected(self, client):
        assert client.get("/api/chats?token=bogus").status_code == 401

    def test_valid_token_is_accepted(self, client):
        token = client.app.state.token
        assert client.get(f"/api/chats?token={token}").status_code == 200

    def test_index_serves_html(self, client):
        assert client.get("/").status_code == 200


class TestI18nEndpoint:
    def test_default_locale(self, client):
        res = client.get("/api/i18n")
        data = res.json()
        assert data["locale"] == "en"
        assert data["direction"] == "ltr"
        assert data["catalog"]["app"]["title"] == "TeleSweep"

    def test_rtl_locale(self, client):
        res = client.get("/api/i18n?lang=fa")
        data = res.json()
        assert data["locale"] == "fa"
        assert data["direction"] == "rtl"

    def test_unknown_locale_falls_back(self, client):
        res = client.get("/api/i18n?lang=xx")
        assert res.json()["locale"] == "en"

    def test_language_list(self, client):
        res = client.get("/api/i18n").json()
        assert "fa" in res["languages"]
        assert res["languages"]["fa"] == "فارسی"


class TestChatsEndpoint:
    def test_returns_all_dialogs(self, populated_client):
        token = populated_client.app.state.token
        res = populated_client.get(f"/api/chats?token={token}")
        data = res.json()
        assert data["total"] == 2

    def test_only_flagged_filter(self, populated_client):
        token = populated_client.app.state.token
        res = populated_client.get(f"/api/chats?token={token}&only_flagged=true")
        data = res.json()
        assert data["total"] == 2
        assert all(d["should_delete"] for d in data["dialogs"])


class TestDeleteEndpoint:
    def test_no_ids_is_rejected(self, populated_client):
        token = populated_client.app.state.token
        res = populated_client.post(
            "/api/delete", json={"token": token, "ids": [], "confirm": False}
        )
        assert res.status_code == 400

    def test_unconfirmed_returns_dry_run_preview(self, populated_client):
        token = populated_client.app.state.token
        res = populated_client.post(
            "/api/delete", json={"token": token, "ids": [100], "confirm": False}
        )
        data = res.json()
        assert data["mode"] == "dry_run_preview"
        assert len(data["preview"]) == 1
        assert data["preview"][0]["name"] == "Spam Bot"

    def test_protected_dialog_is_skipped(self, populated_client):
        token = populated_client.app.state.token
        res = populated_client.post(
            "/api/delete", json={"token": token, "ids": [7770000], "confirm": True}
        )
        data = res.json()
        assert data["total"] == 1
        assert data["results"][0]["result"] == "skipped_protected"

    def test_missing_id_is_not_found(self, populated_client):
        token = populated_client.app.state.token
        res = populated_client.post(
            "/api/delete", json={"token": token, "ids": [999999], "confirm": True}
        )
        assert res.status_code == 404
