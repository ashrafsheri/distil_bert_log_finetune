"""
Email Service
Handles sending emails via SMTP and simple alert cooldown management.
Compatible with Gmail (App Password required).
"""

import os
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

# --- Alert Cooldown Configuration ---
_last_alert_sent_at: datetime | None = None
_cooldown_seconds: int = int(os.getenv("ALERT_COOLDOWN_SECONDS", "3600"))  # default 1 hour


def can_send_alert() -> bool:
    """
    Returns True if an alert can be sent based on the cooldown timer.
    """
    global _last_alert_sent_at
    if _last_alert_sent_at is None:
        return True
    elapsed = datetime.now(timezone.utc) - _last_alert_sent_at
    return elapsed >= timedelta(seconds=_cooldown_seconds)


def mark_alert_sent() -> None:
    """
    Marks that an alert email has been sent, updating the cooldown timer.
    """
    global _last_alert_sent_at
    _last_alert_sent_at = datetime.now(timezone.utc)


def _get_smtp_client():
    """
    Creates and returns an SMTP client using environment variables.

    Expected environment variables:
        SMTP_HOST        (e.g. smtp.gmail.com)
        SMTP_PORT        (e.g. 587)
        SMTP_USERNAME    (your Gmail address)
        SMTP_PASSWORD    (App password, not regular password)
        SMTP_USE_TLS     (true/false)
    """
    host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    port = int(os.getenv("SMTP_PORT", "587"))
    username = os.getenv("SMTP_USERNAME")
    password = os.getenv("SMTP_PASSWORD")
    use_tls = os.getenv("SMTP_USE_TLS", "true").lower() == "true"

    if not host or not username or not password:
        logger.warning(
            "SMTP not configured properly (SMTP_HOST/SMTP_USERNAME/SMTP_PASSWORD missing). Skipping email send."
        )
        return None, None

    try:
        client = smtplib.SMTP(host, port, timeout=10)
        client.ehlo()
        if use_tls:
            client.starttls()
            client.ehlo()
        client.login(username, password)
        return client, username
    except Exception as e:
        logger.error(f"Failed to connect or authenticate to SMTP server: {e}")
        return None, None


def send_email(subject: str, body: str, recipients: List[str]) -> bool:
    """
    Sends an email via configured SMTP server.

    Args:
        subject (str): Email subject
        body (str): Email body (plain text)
        recipients (List[str]): List of recipient email addresses

    Returns:
        bool: True if email sent successfully, False otherwise
    """
    if not recipients:
        logger.info("No recipients provided; skipping email send.")
        return False

    client, sender_username = _get_smtp_client()
    if client is None:
        logger.error("SMTP client not initialized; cannot send email.")
        return False

    sender = os.getenv("SMTP_FROM") or sender_username

    try:
        msg = MIMEMultipart()
        msg["From"] = sender
        msg["To"] = ", ".join(recipients)
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        client.sendmail(sender, recipients, msg.as_string())
        logger.info(f"Alert email sent to {len(recipients)} recipient(s): {recipients}")
        return True
    except Exception as e:
        logger.error(f"Failed to send email: {e}")
        return False
    finally:
        try:
            client.quit()
        except Exception:
            pass
