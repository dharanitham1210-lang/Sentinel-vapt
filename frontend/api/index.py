"""Vercel Serverless Function entry point for SentinelVAPT FastAPI backend."""
import os
import sys
from pathlib import Path

# Add api directory to sys.path so 'app' package is discoverable
api_dir = str(Path(__file__).resolve().parent)
if api_dir not in sys.path:
    sys.path.insert(0, api_dir)

# Ensure Vercel environment variables are set before app imports
os.environ.setdefault("VERCEL", "1")
os.environ.setdefault("CLOUD_MODE", "true")
os.environ.setdefault("STORAGE_BACKEND", "database")
os.environ.setdefault("VULNPILOT_DB", "/tmp/vulnpilot.db")

from app.main import app

