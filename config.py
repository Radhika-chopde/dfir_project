# config.py
import os
from dotenv import load_dotenv

load_dotenv()

DB_CONFIG = {
    "dbname": os.environ.get("DB_NAME", "dfir_db"),
    "user":   os.environ.get("DB_USER", "postgres"),
    "password": os.environ.get("DB_PASSWORD", ""),
    "host":   os.environ.get("DB_HOST", "localhost"),
    "port":   os.environ.get("DB_PORT", "5432"),
}

VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
API_AUTH_TOKEN     = os.environ.get("vit_secure_token_2026", "")