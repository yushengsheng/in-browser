"""Application-owned locations, resolved from this folder on every machine."""
from pathlib import Path

APP_ROOT = Path(__file__).resolve().parent
DATA_ROOT = APP_ROOT / 'data'
