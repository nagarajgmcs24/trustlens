from typing import Optional

from pydantic import BaseModel, Field, field_validator


VALID_CHANNELS = {"SMS", "WhatsApp", "Email", "Other"}
VALID_CHANNEL_ALIASES = {
    "sms": "SMS",
    "whatsapp": "WhatsApp",
    "email": "Email",
    "other": "Other",
}
VALID_LANGUAGES = {
    "english": "English",
    "hindi": "Hindi",
    "kannada": "Kannada",
}


class AnalysisRequest(BaseModel):
    message: str = Field(..., min_length=10, max_length=5000)
    channel: str = Field("Other")
    language: str = Field("English")
    sender_name: Optional[str] = Field(None, max_length=200)
    sender_email: Optional[str] = Field(None, max_length=200)

    @field_validator("channel")
    @classmethod
    def validate_channel(cls, value: str) -> str:
        normalized = (value or "").strip()
        if not normalized:
            return "Other"
        lookup = normalized.casefold()
        if lookup in VALID_CHANNEL_ALIASES:
            return VALID_CHANNEL_ALIASES[lookup]
        if normalized in VALID_CHANNELS:
            return normalized
        return "Other"

    @field_validator("language")
    @classmethod
    def validate_language(cls, value: str) -> str:
        normalized = (value or "").strip().casefold()
        if normalized not in VALID_LANGUAGES:
            raise ValueError("Language must be English, Hindi, or Kannada.")
        return VALID_LANGUAGES[normalized]

    @field_validator("message")
    @classmethod
    def validate_message(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Message cannot be empty.")
        return cleaned


class HistoryRecord(BaseModel):
    analysis_id: str
    timestamp: str
    channel: str
    risk_level: str
    risk_score: int
    detected_categories: list[str]
    message_preview: str
