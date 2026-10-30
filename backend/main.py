from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from settings import APP_ENV, HOST, PORT, configured_origins
from routes.analysis import router as analysis_router

app = FastAPI(title="TRUSTLENS API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=configured_origins(),
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type"],
)

app.include_router(analysis_router)


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=HOST,
        port=PORT,
        reload=APP_ENV == "development",
    )
