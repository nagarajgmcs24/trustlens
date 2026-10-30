import logging
import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv(Path(__file__).resolve().parent / ".env")

logger = logging.getLogger(__name__)
MONGODB_URI = os.getenv("MONGODB_URI")
MONGODB_DB_NAME = os.getenv("MONGODB_DB_NAME", "trustlens")
CONNECTION_TIMEOUT_MS = 3000

client: MongoClient | None = None
db = None
analysis_cache: list[dict[str, Any]] = []


def get_database():
    """Return the configured database only after confirming the connection."""
    global client, db
    if not MONGODB_URI:
        return None

    try:
        if client is None:
            client = MongoClient(
                MONGODB_URI,
                serverSelectionTimeoutMS=CONNECTION_TIMEOUT_MS,
                connectTimeoutMS=CONNECTION_TIMEOUT_MS,
            )
        client.admin.command("ping")
        if db is None:
            db = client[MONGODB_DB_NAME]
        return db
    except Exception as exc:
        logger.warning("MongoDB connection unavailable (%s).", type(exc).__name__)
        if client is not None:
            client.close()
        client = None
        db = None
        return None


def save_history_record(record: dict[str, Any]) -> bool:
    mongo_db = get_database()
    if mongo_db is not None:
        try:
            mongo_db.analysis_history.insert_one(record)
            return True
        except Exception as exc:
            logger.warning("Could not save MongoDB history (%s).", type(exc).__name__)

    analysis_cache.append(record)
    return False


def get_history_records() -> list[dict[str, Any]]:
    mongo_db = get_database()
    if mongo_db is not None:
        try:
            return list(
                mongo_db.analysis_history.find(
                    {},
                    {
                        "_id": 0,
                        "analysis_id": 1,
                        "timestamp": 1,
                        "channel": 1,
                        "risk_level": 1,
                        "risk_score": 1,
                        "detected_categories": 1,
                    },
                ).sort("timestamp", -1).limit(100)
            )
        except Exception as exc:
            logger.warning("Could not retrieve MongoDB history (%s).", type(exc).__name__)

    return list(reversed(analysis_cache[-100:]))


def clear_history() -> int:
    mongo_db = get_database()
    if mongo_db is not None:
        try:
            deleted_count = mongo_db.analysis_history.delete_many({}).deleted_count
            analysis_cache.clear()
            return deleted_count
        except Exception as exc:
            logger.warning("Could not clear MongoDB history (%s).", type(exc).__name__)

    count = len(analysis_cache)
    analysis_cache.clear()
    return count


def database_status() -> str:
    return "connected" if get_database() is not None else "offline"
