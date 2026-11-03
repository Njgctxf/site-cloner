"""
alerts.py - Security Incident & Audit Alert Dispatcher
Sends email notifications and webhook alerts (Slack/Discord/Teams)
when critical vulnerabilities or security posture regressions are detected.
"""

import os
import smtplib
import json
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, Any, Optional
import requests

from .database import log_event

def is_smtp_configured() -> bool:
    return bool(os.environ.get("SMTP_HOST") and os.environ.get("SMTP_USER"))

def send_security_alert_email(recipient_email: str, target_url: str,
                              scan_result: Dict[str, Any]) -> bool:
    """
    Sends a formatted email alert when critical findings are detected.
    """
    if not recipient_email or not is_smtp_configured():
        return False

    host = os.environ.get("SMTP_HOST")
    port = int(os.environ.get("SMTP_PORT", 587))
    user = os.environ.get("SMTP_USER", "")
    password = os.environ.get("SMTP_PASSWORD", "")
    sender = os.environ.get("SMTP_FROM") or user

    score = scan_result.get("risk_score", 0)
    grade = scan_result.get("grade", "F")
    counts = scan_result.get("counts", {})
    criticals = [f for f in scan_result.get("findings", []) if f.get("severity") == "CRITICAL"]
    highs = [f for f in scan_result.get("findings", []) if f.get("severity") == "HIGH"]

    subject = f"🚨 [ALERTE SÉCURITÉ] Vulnérabilités critiques détectées sur {target_url}"

    body_html = f"""
    <html>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #1e293b; background: #f8fafc; padding: 20px;">
        <div style="max-width: 650px; margin: 0 auto; background: #fff; padding: 30px; border-radius: 10px; border: 1px solid #e2e8f0;">
            <div style="border-bottom: 2px solid #ef4444; padding-bottom: 15px; margin-bottom: 20px;">
                <h2 style="color: #ef4444; margin: 0;">🛡️ CyberLab AppSec Alert</h2>
                <div style="font-size: 13px; color: #64748b; margin-top: 5px;">Rapport d'incident automatisé</div>
            </div>
            
            <p>Bonjour,</p>
            <p>Un audit de sécurité planifié sur votre domaine vérifié <strong>{target_url}</strong> a révélé des vulnérabilités nécessitant une remédiation urgente.</p>
            
            <div style="background: #fef2f2; border: 1px solid #fecaca; border-radius: 8px; padding: 15px; margin: 20px 0;">
                <div style="font-size: 14px; color: #991b1b; font-weight: bold;">Score de posture : {score}/100 (Grade {grade})</div>
                <div style="font-size: 13px; color: #7f1d1d; margin-top: 5px;">
                    Failles critiques : <strong>{counts.get('critical', 0)}</strong> &bull; 
                    Failles élevées : <strong>{counts.get('high', 0)}</strong> &bull; 
                    Total anomalies : <strong>{counts.get('total', 0)}</strong>
                </div>
            </div>

            <h3 style="color: #0f172a; font-size: 16px; margin-bottom: 10px;">Vulnérabilités à corriger immédiatement :</h3>
            <ul style="padding-left: 20px;">
    """
    for f in criticals + highs:
        body_html += f"""
            <li style="margin-bottom: 10px;">
                <strong style="color: {'#dc2626' if f.get('severity') == 'CRITICAL' else '#ea580c'};">[{f.get('severity')}] {f.get('title')}</strong><br>
                <span style="font-size: 13px; color: #475569;">{f.get('description')}</span>
            </li>
        """
    body_html += """
            </ul>

            <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #e2e8f0; font-size: 12px; color: #94a3b8; text-align: center;">
                Cet e-mail est généré automatiquement par votre plateforme d'audit CyberLab.
            </div>
        </div>
    </body>
    </html>
    """

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = sender
        msg["To"] = recipient_email
        msg.attach(MIMEText(body_html, "html", "utf-8"))

        with smtplib.SMTP(host, port, timeout=15) as s:
            s.starttls()
            if user and password:
                s.login(user, password)
            s.send_message(msg)

        log_event("ALERT_EMAIL_SENT", "INFO", "ALERT_MGR", f"E-mail d'alerte sécurité envoyé à {recipient_email} pour {target_url}")
        return True
    except Exception as e:
        log_event("ALERT_EMAIL_FAILED", "WARN", "ALERT_MGR", f"Échec de l'envoi d'alerte e-mail à {recipient_email}: {e}")
        return False

def send_security_alert_webhook(webhook_url: str, target_url: str,
                                scan_result: Dict[str, Any]) -> bool:
    """
    Sends a formatted JSON webhook (compatible Slack / Teams / Discord) on alert.
    """
    if not webhook_url:
        return False

    counts = scan_result.get("counts", {})
    score = scan_result.get("risk_score", 0)
    grade = scan_result.get("grade", "F")

    payload = {
        "text": f"🚨 *[CyberLab Alert]* Failles détectées sur {target_url} (Score {score}/100 - Grade {grade})",
        "attachments": [
            {
                "color": "#ef4444" if counts.get("critical", 0) > 0 else "#f97316",
                "title": f"Rapport d'audit pour {target_url}",
                "fields": [
                    {"title": "Critiques (P1)", "value": str(counts.get("critical", 0)), "short": True},
                    {"title": "Élevées (P2)", "value": str(counts.get("high", 0)), "short": True},
                    {"title": "Moyennes (P3)", "value": str(counts.get("medium", 0)), "short": True},
                    {"title": "Score Global", "value": f"{score}/100", "short": True}
                ],
                "footer": "CyberLab AppSec Engine",
                "ts": int(scan_result.get("timestamp_epoch", 0))
            }
        ]
    }

    try:
        res = requests.post(webhook_url, json=payload, timeout=5)
        ok = res.status_code in (200, 204)
        if ok:
            log_event("ALERT_WEBHOOK_SENT", "INFO", "ALERT_MGR", f"Webhook d'alerte délivré pour {target_url}")
        return ok
    except Exception as e:
        log_event("ALERT_WEBHOOK_FAILED", "WARN", "ALERT_MGR", f"Échec d'envoi du webhook: {e}")
        return False

def dispatch_scan_alerts(target_url: str, scan_result: Dict[str, Any],
                        recipient_email: Optional[str] = None):
    """
    Evaluates scan findings and triggers alerts if critical or high issues are found.
    """
    counts = scan_result.get("counts", {})
    critical_count = counts.get("critical", 0)
    high_count = counts.get("high", 0)

    # Only alert if critical or high vulnerabilities are detected
    if critical_count == 0 and high_count == 0:
        return

    # 1. Email notification
    target_email = recipient_email or os.environ.get("SECURITY_ALERT_EMAIL")
    if target_email:
        send_security_alert_email(target_email, target_url, scan_result)

    # 2. Webhook notification
    webhook_url = os.environ.get("SECURITY_ALERT_WEBHOOK")
    if webhook_url:
        send_security_alert_webhook(webhook_url, target_url, scan_result)


def dispatch_live_attack_alert(domain: str, source_ip: str, severity: str, summary: str,
                               recipient_email: Optional[str] = None):
    """
    Fired by Sentinel's real-time monitor the moment an attack in progress is
    confirmed on a protected site (as opposed to dispatch_scan_alerts, which
    fires after a passive/active audit scan completes).
    """
    target_email = recipient_email or os.environ.get("SECURITY_ALERT_EMAIL")
    if target_email and is_smtp_configured():
        try:
            host = os.environ.get("SMTP_HOST")
            port = int(os.environ.get("SMTP_PORT", 587))
            user = os.environ.get("SMTP_USER", "")
            password = os.environ.get("SMTP_PASSWORD", "")
            sender = os.environ.get("SMTP_FROM") or user

            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"🚨 [SENTINEL] Attaque en cours détectée sur {domain}"
            msg["From"] = sender
            msg["To"] = target_email
            msg.attach(MIMEText(
                f"Sentinel a détecté et bloqué une attaque en cours.\n\n"
                f"Domaine : {domain}\nIP source : {source_ip}\nGravité : {severity}\n\n{summary}\n",
                "plain"))

            with smtplib.SMTP(host, port) as server:
                server.starttls()
                server.login(user, password)
                server.sendmail(sender, [target_email], msg.as_string())
            log_event("SENTINEL_ALERT_EMAIL_SENT", "INFO", "ALERT_MGR", f"Alerte live envoyée pour {domain}")
        except Exception as e:
            log_event("SENTINEL_ALERT_EMAIL_FAILED", "WARN", "ALERT_MGR", f"Échec de l'alerte live par email: {e}")

    webhook_url = os.environ.get("SECURITY_ALERT_WEBHOOK")
    if webhook_url:
        try:
            payload = {
                "text": f"🚨 *[SENTINEL LIVE]* Attaque bloquée sur {domain}",
                "attachments": [{
                    "color": "#ef4444" if severity in ("CRITICAL", "HIGH") else "#f97316",
                    "title": f"IP source : {source_ip} - Gravité : {severity}",
                    "text": summary,
                }]
            }
            res = requests.post(webhook_url, json=payload, timeout=5)
            if res.status_code in (200, 204):
                log_event("SENTINEL_ALERT_WEBHOOK_SENT", "INFO", "ALERT_MGR", f"Alerte live webhook envoyée pour {domain}")
        except Exception as e:
            log_event("SENTINEL_ALERT_WEBHOOK_FAILED", "WARN", "ALERT_MGR", f"Échec webhook alerte live: {e}")
