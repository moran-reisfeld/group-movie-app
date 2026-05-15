import smtplib
import ssl
import uuid
from email.mime.text import MIMEText

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

SMTP_EMAIL = "moran.reisfeld@gmail.com"
SMTP_PASSWORD = "svoa lhpc amre cyhf".strip()

SMTP_TIMEOUT = 10


def generate_security_code():
    security_code = str(uuid.uuid4())
    half_length = len(security_code) // 2
    return security_code[:half_length]


def send_email(to_email, subject, body):
    msg = MIMEText(body)
    msg["From"] = SMTP_EMAIL
    msg["To"] = to_email
    msg["Subject"] = subject

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=SMTP_TIMEOUT) as server:
            context = ssl.create_default_context()
            server.starttls(context=context)
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as e:
        print("SMTP error:", e)
        return False


def send_signup_code(email, code):
    subject = "Signup Verification Code"
    body = f"Your signup verification code is: {code}"
    return send_email(email, subject, body)


def send_reset_code(email, code):
    subject = "Password Reset Code"
    body = f"Your password reset code is: {code}"
    return send_email(email, subject, body)