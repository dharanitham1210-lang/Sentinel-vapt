import os
import secrets
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent

# ---------------- Cloud Mode & Environment ----------------
IS_VERCEL = bool(os.getenv("VERCEL"))
CLOUD_MODE = IS_VERCEL or os.getenv("CLOUD_MODE", "false").strip().lower() in ("true", "1", "yes")

# Storage backend: 'database' (recommended for ephemeral cloud like Render/Vercel) or 'local'
STORAGE_BACKEND = os.getenv("STORAGE_BACKEND", "database" if CLOUD_MODE else "local").strip().lower()

# Server Port
PORT = int(os.getenv("PORT", "8000"))

# Secret Key for JWT & signed tokens
_env_secret = os.getenv("SECRET_KEY") or os.getenv("AUTH_SECRET_KEY")
if not _env_secret:
    if CLOUD_MODE:
        # In cloud mode, require a strong secret or generate one securely per instance
        _env_secret = secrets.token_urlsafe(32)
    else:
        _env_secret = "sentinel-vapt-dev-secret-key-change-in-production"
SECRET_KEY = _env_secret

# ---------------- Database Connection ----------------
# - Local / default: SQLite file path (VULNPILOT_DB).
# - Production: PostgreSQL connection string (postgresql:// or postgres://) e.g. from Neon.
# - Vercel Serverless: default to /tmp/vulnpilot.db where filesystem is writable.
_default_db = "/tmp/vulnpilot.db" if IS_VERCEL else str(BASE_DIR / "vulnpilot.db")
_vuln_db = os.getenv("VULNPILOT_DB", _default_db)
_database_url = os.getenv("DATABASE_URL", "").strip()

if _database_url.lower().startswith(("postgresql://", "postgres://")):
    DATABASE_URL = _database_url
else:
    DATABASE_URL = _vuln_db

# ---------------- CORS / Allowed Origins ----------------
# Comma-separated list of origins, e.g. "https://my-app.vercel.app,http://localhost:5173"
_origins_env = os.getenv("ALLOWED_ORIGINS") or os.getenv("CORS_ORIGINS") or os.getenv("FRONTEND_URL") or "*"
ALLOWED_ORIGINS = [o.strip().rstrip("/") for o in _origins_env.split(",") if o.strip()] or ["*"]

# ---------------- Admin Account (from env vars) ----------------
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "").strip()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "").strip()

# ---------------- LLM Configuration ----------------
LLM_API_KEY = os.getenv("LLM_API_KEY", "").strip()
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "https://api.openai.com/v1").strip()
LLM_MODEL = os.getenv("LLM_MODEL", "gpt-4o-mini").strip()

# ---------------- Scanner Endpoints ----------------
ZAP_API_URL = os.getenv("ZAP_API_URL", "http://127.0.0.1:8090").strip()
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "").strip()

# ---------------- File Paths (Fallback / Local Storage) ----------------
_default_base = Path("/tmp") if IS_VERCEL else BASE_DIR
UPLOAD_DIR = os.getenv("UPLOAD_DIR", str(_default_base / "uploads"))
REPORTS_DIR = os.getenv("REPORTS_DIR", str(_default_base / "reports"))
ARTIFACTS_DIR = os.getenv("ARTIFACTS_DIR", str(_default_base / "artifacts"))

Path(UPLOAD_DIR).mkdir(parents=True, exist_ok=True)
Path(REPORTS_DIR).mkdir(parents=True, exist_ok=True)
Path(ARTIFACTS_DIR).mkdir(parents=True, exist_ok=True)

# ---------------- Optional Supabase Storage ----------------
SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip().rstrip("/")
SUPABASE_SERVICE_KEY = (
    os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()
    or os.getenv("SUPABASE_KEY", "").strip()
)
SUPABASE_UPLOADS_BUCKET = os.getenv("SUPABASE_UPLOADS_BUCKET", "vulnpilot-uploads").strip() or "vulnpilot-uploads"
SUPABASE_REPORTS_BUCKET = os.getenv("SUPABASE_REPORTS_BUCKET", "vulnpilot-reports").strip() or "vulnpilot-reports"
