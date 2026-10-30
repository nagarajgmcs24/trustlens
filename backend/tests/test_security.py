import asyncio

import pytest
from fastapi import HTTPException

import routes.analysis as analysis_routes
from models.schemas import AnalysisRequest
from settings import configured_origins, history_api_enabled


def test_history_is_disabled_in_production_even_if_requested(monkeypatch):
    assert history_api_enabled("production", requested=True) is False
    assert history_api_enabled("development", requested=True) is True
    assert history_api_enabled("development", requested=False) is False


def test_history_endpoints_reject_when_disabled(monkeypatch):
    monkeypatch.setattr(analysis_routes, "ENABLE_HISTORY_API", False)

    with pytest.raises(HTTPException) as read_error:
        asyncio.run(analysis_routes.list_history())
    with pytest.raises(HTTPException) as delete_error:
        asyncio.run(analysis_routes.clear_analysis_history())

    assert read_error.value.status_code == 404
    assert delete_error.value.status_code == 404


def test_cors_origins_reject_wildcard(monkeypatch):
    monkeypatch.setenv("CORS_ORIGINS", "*")

    with pytest.raises(ValueError, match="explicit HTTP"):
        configured_origins()


def test_cors_origins_accept_explicit_frontend(monkeypatch):
    monkeypatch.setenv("CORS_ORIGINS", "https://demo.example.com")

    assert configured_origins() == ["https://demo.example.com"]


def test_cors_origins_reject_path_and_invalid_port(monkeypatch):
    for origin in ("https://demo.example.com/app", "https://demo.example.com:invalid"):
        monkeypatch.setenv("CORS_ORIGINS", origin)
        with pytest.raises(ValueError, match="valid origins"):
            configured_origins()


def test_analysis_persists_metadata_without_original_message(monkeypatch):
    saved_records = []
    monkeypatch.setattr(analysis_routes, "save_history_record", saved_records.append)
    original_message = "Your account is locked; verify your bank details now."

    asyncio.run(
        analysis_routes.analyze_message_endpoint(
            AnalysisRequest(message=original_message, channel="SMS")
        )
    )

    assert len(saved_records) == 1
    assert "message" not in saved_records[0]
    assert original_message not in repr(saved_records[0])
