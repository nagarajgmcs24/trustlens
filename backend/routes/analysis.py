from fastapi import APIRouter, HTTPException

from database import clear_history, database_status, get_history_records, save_history_record
from models.schemas import AnalysisRequest
from settings import ENABLE_HISTORY_API
from services.detection_engine import analyze_message

router = APIRouter()


@router.get("/")
async def root():
    return {"message": "TRUSTLENS API is running."}


@router.get("/api/health")
async def health_check():
    return {
        "status": "ok",
        "database": database_status(),
        "message": "Backend is healthy and ready for analysis.",
    }


@router.post("/api/analyze")
async def analyze_message_endpoint(payload: AnalysisRequest):
    if not payload.message or not payload.message.strip():
        raise HTTPException(status_code=400, detail="Message cannot be empty.")

    result = analyze_message(
        message=payload.message,
        channel=payload.channel,
        language=payload.language,
        sender_name=payload.sender_name,
        sender_email=payload.sender_email,
    )

    save_history_record({
        "analysis_id": result["analysis_id"],
        "timestamp": result["timestamp"],
        "channel": payload.channel,
        "risk_level": result["risk_level"],
        "risk_score": result["risk_score"],
        "detected_categories": result["detected_categories"],
    })

    return result


@router.get("/api/history")
async def list_history():
    if not ENABLE_HISTORY_API:
        raise HTTPException(status_code=404, detail="History is disabled in this deployment.")
    return {"history": get_history_records()}


@router.delete("/api/history")
async def clear_analysis_history():
    if not ENABLE_HISTORY_API:
        raise HTTPException(status_code=404, detail="History is disabled in this deployment.")
    deleted_count = clear_history()
    return {"success": True, "deleted_count": deleted_count}
