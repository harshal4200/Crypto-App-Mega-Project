from config import Config
import smtplib
from email.mime.text import MIMEText

def send_email(to_email: str, subject: str, body: str) -> bool:
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = f"{Config.SMTP_FROM_NAME} <{Config.SMTP_USER}>"
    msg["To"] = to_email

    try:
        server = smtplib.SMTP(Config.SMTP_HOST, Config.SMTP_PORT, timeout=20)
        if Config.SMTP_USE_TLS:
            server.starttls()
        server.login(Config.SMTP_USER, Config.SMTP_PASS)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print("SMTP error:", e)
        return False
