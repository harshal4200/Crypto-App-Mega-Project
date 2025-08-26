import os
from dotenv import load_dotenv

load_dotenv("secrets.env")  # make sure your env file is named correctly

class Config:
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "supersecretkey")  # ✅ FIXED (Flask-WTF expects SECRET_KEY)
    
    # Database
    DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
    DB_PORT = int(os.getenv("DB_PORT", 3306))
    DB_USER = os.getenv("DB_USER", "root")
    DB_PASSWORD = os.getenv("DB_PASSWORD")  # make sure this is read correctly
    DB_NAME = os.getenv("DB_NAME", "crypto_app")

    # OpenAI
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

    # Google OAuth
    GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
    GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
    GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")

    # SMTP
    SMTP_HOST = os.getenv("SMTP_HOST")
    SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
    SMTP_USER = os.getenv("SMTP_USER")
    SMTP_PASS = os.getenv("SMTP_PASS")
    SMTP_FROM_NAME = os.getenv("SMTP_FROM_NAME")
    SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").lower() == "true"
