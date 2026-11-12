import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pymongo.errors import PyMongoError
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.config.settings import settings
from app.config.database import db_manager
from app.services.prediction_service import prediction_service
from app.utils.dependencies import limiter

from app.routes.auth import router as auth_router
from app.routes.scanner import router as scanner_router
from app.routes.history import router as history_router
from app.routes.dashboard import router as dashboard_router
from app.routes.reports import router as reports_router
from app.routes.intelligence import router as intelligence_router

# Configure logging
logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("phishguard.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifecycle management.
    Connects to database and loads ML model on startup; cleans up on shutdown.
    """
    logger.info("Initializing %s v%s...", settings.APP_NAME, settings.APP_VERSION)

    # 1. MongoDB Connection
    await db_manager.connect_to_database()

    # 2. Scikit-learn Model Initialization
    prediction_service.load_model()

    yield

    # Shutdown
    logger.info("Shutting down %s...", settings.APP_NAME)
    await db_manager.close_database_connection()


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="AI-Powered Phishing Detection and Website Security Analysis Platform REST API",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Attach rate limiter to application state
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# Centralized Exception Handlers
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Clean validation error formatting without raw stack traces."""
    errors = []
    for error in exc.errors():
        field = ".".join(str(loc) for loc in error["loc"] if loc != "body")
        errors.append({"field": field or "body", "message": error["msg"]})
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"success": False, "message": "Invalid request payload.", "errors": errors},
    )


@app.exception_handler(PyMongoError)
async def pymongo_exception_handler(request: Request, exc: PyMongoError):
    """Catch-all MongoDB database exception handler returning clean HTTP 503 instead of 500."""
    logger.error("Database error processing request %s: %s", request.url.path, exc)
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={
            "success": False,
            "message": "Database connection is temporarily unavailable. Please try again later.",
            "detail": "Database connection is temporarily unavailable. Please try again later.",
        },
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Catch-all unhandled exception handler that prevents leaking internals."""
    logger.error("Unhandled exception processing request %s: %s", request.url.path, exc, exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "success": False,
            "message": "An internal server error occurred. Our security monitoring has logged this incident.",
        },
    )


# CORS Configuration for Next.js Frontend
origins = [
    settings.FRONTEND_URL,
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition"],
)


# Health Endpoint
@app.get("/health", tags=["System Health"], summary="Comprehensive Health Check")
async def health_check(response: Response):
    """
    Return operational status of the API, MongoDB Atlas connectivity,
    ML model availability, and Threat Intelligence feeds.
    Returns HTTP 503 if required database dependencies are unavailable.
    """
    is_db_connected = db_manager.is_connected
    db_status = "connected" if is_db_connected else "disconnected"
    ml_status = prediction_service.get_status()

    # Mark non-success HTTP status if database is unavailable
    if not is_db_connected:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": "healthy" if is_db_connected else "unhealthy",
        "api": "running",
        "app_name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "database": {
            "status": db_status,
            "connected": is_db_connected,
            "database_name": settings.DATABASE_NAME if is_db_connected else None,
            "error": db_manager.connection_error if not is_db_connected else None,
        },
        "ml_model": {
            "status": "ready" if ml_status["available"] else "unavailable",
            "available": ml_status["available"],
            "model_version": ml_status["model_version"],
            "message": ml_status["message"],
        },
        "threat_intelligence": {
            "phishtank_configured": bool(settings.PHISHTANK_API_KEY),
            "openphish_configured": bool(settings.OPENPHISH_API_KEY),
        },
    }


# Include Versioned API Routers
app.include_router(auth_router, prefix=settings.API_V1_PREFIX)
app.include_router(scanner_router, prefix=settings.API_V1_PREFIX)
app.include_router(history_router, prefix=settings.API_V1_PREFIX)
app.include_router(dashboard_router, prefix=settings.API_V1_PREFIX)
app.include_router(reports_router, prefix=settings.API_V1_PREFIX)
app.include_router(intelligence_router, prefix=settings.API_V1_PREFIX)

