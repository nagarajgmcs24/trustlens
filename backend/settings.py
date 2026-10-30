import os
from pathlib import Path
from urllib.parse import urlsplit

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")

APP_ENV = os.getenv("APP_ENV", "development").strip().lower()
if APP_ENV not in {"development", "production"}:
    raise ValueError("APP_ENV must be 'development' or 'production'.")


def parse_bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"true", "1", "yes", "on"}:
        return True
    if normalized in {"false", "0", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean value.")


def configured_origins() -> list[str]:
    raw_origins = os.getenv("CORS_ORIGINS")
    if raw_origins is None:
        if APP_ENV == "production":
            raise ValueError("CORS_ORIGINS must contain at least one production frontend origin.")
        raw_origins = "http://localhost:5173,http://127.0.0.1:5173"

    origins = [origin.strip() for origin in raw_origins.split(",") if origin.strip()]
    for origin in origins:
        if origin == "*":
            raise ValueError("CORS_ORIGINS must contain explicit HTTP(S) origins, not wildcards.")
        parsed = urlsplit(origin)
        try:
            valid_port = parsed.port is None or 1 <= parsed.port <= 65535
        except ValueError:
            valid_port = False
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
            or not valid_port
        ):
            raise ValueError("CORS_ORIGINS must contain valid origins without paths or credentials.")
    if not origins:
        raise ValueError("CORS_ORIGINS must contain at least one frontend origin.")
    return origins


def history_api_enabled(app_env: str, requested: bool) -> bool:
    return app_env == "development" and requested


ENABLE_HISTORY_API = history_api_enabled(
    APP_ENV,
    parse_bool_env("ENABLE_HISTORY_API", default=True),
)
HOST = os.getenv("HOST", "127.0.0.1" if APP_ENV == "development" else "0.0.0.0")
PORT = int(os.getenv("PORT", "8000"))
