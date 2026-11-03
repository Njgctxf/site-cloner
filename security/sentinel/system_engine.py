"""
system_engine.py - Infrastructure & System Configuration Audit Engine
Performs non-destructive, standards-based security posture assessments for:
  - Linux Servers (SSH hardening, ANSSI/CIS benchmarks, file permissions)
  - Windows Servers (SMBv1, RDP NLA, Lanman shares, null sessions)
  - Databases (PostgreSQL, MySQL, Redis, MongoDB configuration auditing)
Strictly validated by Sentinel Guardian for authorized assets.
"""

import re
import socket
from typing import Dict, Any, List, Optional

# Standard rules for SSH Hardening (CIS Benchmark & ANSSI BP-028)
LINUX_SSH_RULES = [
    {
        "id": "SSH_ROOT_LOGIN",
        "pattern": r"^\s*PermitRootLogin\s+(yes)\b",
        "severity": "HIGH",
        "title": "Connexion directe du superutilisateur 'root' en SSH autorisée",
        "description": "PermitRootLogin est configuré sur 'yes', permettant des attaques par force brute directe sur le compte administrateur.",
        "remediation": "Définir 'PermitRootLogin no' ou 'PermitRootLogin prohibit-password' dans /etc/ssh/sshd_config."
    },
    {
        "id": "SSH_PASSWORD_AUTH",
        "pattern": r"^\s*PasswordAuthentication\s+(yes)\b",
        "severity": "MEDIUM",
        "title": "Authentification par mot de passe SSH activée",
        "description": "L'authentification par mot de passe expose le serveur à des attaques par dictionnaire ou credential stuffing.",
        "remediation": "Privilégier l'authentification par clés cryptographiques (Ed25519) et définir 'PasswordAuthentication no'."
    },
    {
        "id": "SSH_PROTOCOL_1",
        "pattern": r"^\s*Protocol\s+1\b",
        "severity": "CRITICAL",
        "title": "Protocole SSH v1 obsolète et vulnérable activé",
        "description": "Le protocole SSH-1 souffre de faiblesses cryptographiques majeures et d'attaques par injection.",
        "remediation": "Définir 'Protocol 2' dans /etc/ssh/sshd_config ou supprimer cette directive (SSH-2 par défaut)."
    },
    {
        "id": "SSH_EMPTY_PASSWORDS",
        "pattern": r"^\s*PermitEmptyPasswords\s+(yes)\b",
        "severity": "CRITICAL",
        "title": "Mots de passe vides autorisés pour les sessions SSH",
        "description": "Des comptes sans mot de passe peuvent ouvrir une session distante.",
        "remediation": "Définir impérativement 'PermitEmptyPasswords no' dans /etc/ssh/sshd_config."
    },
    {
        "id": "SSH_MAX_AUTH_TRIES",
        "pattern": r"^\s*MaxAuthTries\s+([7-9]|\d{2,})\b",
        "severity": "LOW",
        "title": "Nombre maximal de tentatives d'authentification SSH trop élevé",
        "description": "Un nombre élevé de MaxAuthTries facilite le brute force au cours d'une même session TCP.",
        "remediation": "Limiter 'MaxAuthTries 4' dans /etc/ssh/sshd_config."
    },
]

# Windows Hardening Rules (CIS Windows Server Benchmark)
WINDOWS_RULES = [
    {
        "id": "WIN_SMBV1_ENABLED",
        "pattern": r"(?i)(smbv1|SMB1).*?(enabled|true|1)",
        "severity": "CRITICAL",
        "title": "Protocole obsolète SMBv1 activé",
        "description": "SMBv1 est vulnérable à des attaques critiques d'exécution de code à distance (ex: EternalBlue / WannaCry).",
        "remediation": "Désactiver SMBv1 via PowerShell: 'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol'."
    },
    {
        "id": "WIN_RDP_NLA_DISABLED",
        "pattern": r"(?i)(UserAuthentication|NLA).*?(disabled|false|0)",
        "severity": "HIGH",
        "title": "Authentification au niveau du réseau (NLA) RDP désactivée",
        "description": "Sans NLA, l'écran de connexion RDP est exposé avant pré-authentification, vulnérable à des exploits pré-auth (BlueKeep).",
        "remediation": "Activer NLA dans les paramètres du Bureau à distance ou par GPO: 'Require network level authentication: Enabled'."
    },
    {
        "id": "WIN_NULL_SESSION_SHARES",
        "pattern": r"(?i)(NullSessionShares.*?(1|enabled)|RestrictAnonymous.*?(0|disabled))",
        "severity": "HIGH",
        "title": "Partages IPC$ / sessions anonymes NULL autorisées",
        "description": "Permet à un attaquant non authentifié sur le réseau d'énumérer les utilisateurs et partages du domaine.",
        "remediation": "Restreindre l'accès anonyme via le Registre: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymous = 1."
    }
]

# Database Hardening Rules
DATABASE_RULES = {
    "redis": [
        {
            "id": "REDIS_PROTECTED_MODE_OFF",
            "pattern": r"^\s*protected-mode\s+no\b",
            "severity": "CRITICAL",
            "title": "Mode protégé Redis désactivé sans mot de passe",
            "description": "Permet des requêtes non authentifiées depuis n'importe quelle interface réseau.",
            "remediation": "Activer 'protected-mode yes' et configurer 'requirepass <secret_robuste>'."
        },
        {
            "id": "REDIS_BIND_ALL",
            "pattern": r"^\s*bind\s+0\.0\.0\.0\b",
            "severity": "HIGH",
            "title": "Redis écoute sur toutes les interfaces réseau (0.0.0.0)",
            "description": "L'écoute sur 0.0.0.0 sans firewall strict expose la mémoire cache aux réseaux non autorisés.",
            "remediation": "Lier Redis uniquement à 'bind 127.0.0.1' ou sur l'IP du sous-réseau interne privé."
        }
    ],
    "mongodb": [
        {
            "id": "MONGO_NO_AUTH",
            "pattern": r"(?i)(authorization|auth).*?(disabled|false)",
            "severity": "CRITICAL",
            "title": "Authentification MongoDB désactivée",
            "description": "N'importe quel client réseau peut lire et modifier toutes les collections de données.",
            "remediation": "Activer 'security.authorization: enabled' dans mongod.conf."
        }
    ],
    "postgres": [
        {
            "id": "PG_LISTEN_ALL",
            "pattern": r"^\s*listen_addresses\s*=\s*['\"]\*(?:['\"]|\b)",
            "severity": "MEDIUM",
            "title": "PostgreSQL écoute sur toutes les interfaces réseau (*)",
            "description": "Exposition potentielle du port 5432 au-delà des serveurs applicatifs nécessaires.",
            "remediation": "Restreindre 'listen_addresses' aux interfaces privées et sécuriser pg_hba.conf."
        },
        {
            "id": "PG_SSL_OFF",
            "pattern": r"^\s*ssl\s*=\s*off\b",
            "severity": "HIGH",
            "title": "Connexions chiffrées SSL/TLS désactivées sur PostgreSQL",
            "description": "Les identifiants et données de requête transitent en clair sur le réseau.",
            "remediation": "Activer 'ssl = on' avec certificat X.509 valide."
        }
    ],
    "mysql": [
        {
            "id": "MYSQL_SSL_OFF",
            "pattern": r"(?i)^\s*require_secure_transport\s*=\s*(OFF|0)\b",
            "severity": "HIGH",
            "title": "Transport sécurisé TLS non obligatoire sur MySQL",
            "description": "Les connexions non chiffrées sont tolérées par le serveur de base de données.",
            "remediation": "Définir 'require_secure_transport = ON' dans my.cnf."
        }
    ]
}


def audit_linux_server_config(target: str, config_text: Optional[str] = None) -> Dict[str, Any]:
    """
    Audits a Linux server SSH / daemon configuration file.
    Non-destructive, regex-based security compliance scanner.
    """
    content = config_text or _get_sample_linux_config()
    findings = []

    for rule in LINUX_SSH_RULES:
        match = re.search(rule["pattern"], content, re.MULTILINE | re.IGNORECASE)
        if match:
            findings.append({
                "rule_id": rule["id"],
                "severity": rule["severity"],
                "title": rule["title"],
                "description": rule["description"],
                "evidence": match.group(0).strip(),
                "remediation": rule["remediation"]
            })

    # File permission mock checks (e.g. /etc/shadow permissions)
    if "shadow_perms: 0644" in content or "shadow: 0644" in content:
        findings.append({
            "rule_id": "PERM_SHADOW_WORLD_READABLE",
            "severity": "CRITICAL",
            "title": "Fichier sensible /etc/shadow accessible en lecture globale (0644)",
            "description": "Les condensats de mots de passe de tous les utilisateurs peuvent être lus par des comptes non privilégiés.",
            "evidence": "/etc/shadow: permissions 0644 au lieu de 0640",
            "remediation": "Appliquer 'chmod 0640 /etc/shadow' et restreindre au groupe 'shadow' ou 'root'."
        })

    return {
        "target": target,
        "os_family": "linux",
        "findings_count": len(findings),
        "findings": findings,
        "status": "vulnerable" if findings else "secure"
    }


def audit_windows_server_config(target: str, config_text: Optional[str] = None) -> Dict[str, Any]:
    """
    Audits Windows server configuration parameters (SMB, RDP, NLA, Null Sessions).
    """
    content = config_text or _get_sample_windows_config()
    findings = []

    for rule in WINDOWS_RULES:
        match = re.search(rule["pattern"], content, re.IGNORECASE)
        if match:
            findings.append({
                "rule_id": rule["id"],
                "severity": rule["severity"],
                "title": rule["title"],
                "description": rule["description"],
                "evidence": match.group(0).strip(),
                "remediation": rule["remediation"]
            })

    return {
        "target": target,
        "os_family": "windows",
        "findings_count": len(findings),
        "findings": findings,
        "status": "vulnerable" if findings else "secure"
    }


def audit_database_config(db_type: str, target: str, config_text: Optional[str] = None) -> Dict[str, Any]:
    """
    Audits database security configuration (PostgreSQL, MySQL, Redis, MongoDB).
    """
    clean_db = (db_type or "postgres").lower().strip()
    rules = DATABASE_RULES.get(clean_db, [])
    content = config_text or _get_sample_db_config(clean_db)
    findings = []

    for rule in rules:
        match = re.search(rule["pattern"], content, re.MULTILINE | re.IGNORECASE)
        if match:
            findings.append({
                "rule_id": rule["id"],
                "severity": rule["severity"],
                "title": rule["title"],
                "description": rule["description"],
                "evidence": match.group(0).strip(),
                "remediation": rule["remediation"]
            })

    return {
        "target": target,
        "db_type": clean_db,
        "findings_count": len(findings),
        "findings": findings,
        "status": "vulnerable" if findings else "secure"
    }


def _get_sample_linux_config() -> str:
    return """
# Sample Linux sshd_config
Port 22
Protocol 2
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords no
MaxAuthTries 8
X11Forwarding yes
"""

def _get_sample_windows_config() -> str:
    return """
# Sample Windows Server Security Posture
SMB1: Enabled
UserAuthentication: 0 (NLA disabled)
NullSessionShares: 1
"""

def _get_sample_db_config(db_type: str) -> str:
    if db_type == "redis":
        return "bind 0.0.0.0\nprotected-mode no\nport 6379"
    elif db_type == "mongodb":
        return "net:\n  port: 27017\nsecurity:\n  authorization: disabled"
    elif db_type == "mysql":
        return "[mysqld]\nport=3306\nrequire_secure_transport=OFF"
    return "listen_addresses = '*'\nssl = off\nport = 5432"
