"""
Pytest configuration: set up sys.path and required environment variables
before any test module is collected or imported.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# backend/ must be on sys.path so that `from app.*` imports work for all
# test modules, including backtest_harness.py which is loaded dynamically.
BACKEND_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_DIR.parent

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

# realtime_anomaly_detection/models/ is needed by tests that import
# project_manager directly (without going through the package).
ANOMALY_MODELS_DIR = REPO_ROOT / "realtime_anomaly_detection" / "models"
if str(ANOMALY_MODELS_DIR) not in sys.path:
    sys.path.insert(0, str(ANOMALY_MODELS_DIR))

# Provide a dummy DATABASE_URL so SQLAlchemy engine construction doesn't raise
# at import time.  The engine is lazy; no actual DB connection is made.
os.environ.setdefault(
    "DATABASE_URL",
    "postgresql+asyncpg://postgres:postgres@localhost/test_db",
)
