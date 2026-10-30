"""
network_guard.py - Anti-SSRF, DNS Rebinding Protection & Network Safety Guard
Prevents the security scanner from targeting private networks, internal cloud metadata,
local loopbacks, or engaging in unauthorized scans.
"""

import ipaddress
import socket
import urllib.parse
from typing import Tuple, List, Optional
import requests

# Local lab hosts explicitly permitted only for the educational sandbox
LAB_HOSTS = {
    "localhost",
    "127.0.0.1",
    "::1",
    "0.0.0.0",
    "innotech-lab.local",
    "cyberlab.local",
}

# Blocked IP ranges (RFC 1918, RFC 3927 link-local, RFC 5735 loopback, Cloud metadata)
DISALLOWED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Current network
    ipaddress.ip_network("10.0.0.0/8"),          # RFC 1918 private
    ipaddress.ip_network("100.64.0.0/10"),       # Carrier-grade NAT
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),      # Link-local (AWS/GCP/Azure metadata 169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),       # RFC 1918 private
    ipaddress.ip_network("192.0.0.0/24"),        # IETF protocol assignments
    ipaddress.ip_network("192.0.2.0/24"),        # TEST-NET-1
    ipaddress.ip_network("192.88.99.0/24"),      # 6to4 relay
    ipaddress.ip_network("192.168.0.0/16"),      # RFC 1918 private
    ipaddress.ip_network("198.18.0.0/15"),       # Benchmark testing
    ipaddress.ip_network("198.51.100.0/24"),     # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),      # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),         # Multicast
    ipaddress.ip_network("240.0.0.0/4"),         # Reserved for future use
    ipaddress.ip_network("255.255.255.255/32"),  # Broadcast
    # IPv6 Disallowed
    ipaddress.ip_network("::1/128"),             # Loopback
    ipaddress.ip_network("::/128"),              # Unspecified
    ipaddress.ip_network("fc00::/7"),            # Unique local address (ULA)
    ipaddress.ip_network("fe80::/10"),           # Link-local
    ipaddress.ip_network("ff00::/8"),            # Multicast
]

def is_safe_ip(ip_str: str) -> Tuple[bool, str]:
    """
    Checks if an IP address is a safe, publicly routable address.
    Rejects private networks, loopbacks, link-local (cloud metadata), and reserved ranges.
    """
    try:
        ip = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return False, f"Adresse IP syntaxiquement invalide: '{ip_str}'"

    if ip.is_loopback:
        return False, f"Accès refusé: IP de boucle locale interdite ({ip})"
    if ip.is_private:
        return False, f"Accès refusé: IP de réseau privé (RFC 1918) interdite ({ip})"
    if ip.is_link_local:
        return False, f"Accès refusé: IP de lien local / métadonnées cloud interdite ({ip})"
    if ip.is_multicast:
        return False, f"Accès refusé: IP multicast interdite ({ip})"
    if ip.is_reserved:
        return False, f"Accès refusé: IP réservée interdite ({ip})"

    for net in DISALLOWED_NETWORKS:
        if ip in net:
            return False, f"Accès refusé: L'adresse IP {ip} appartient à une plage réseau interdite ({net})"

    return True, "IP publique autorisée"

def resolve_and_validate_hostname(hostname: str, allow_local_lab: bool = False) -> Tuple[bool, List[str], str]:
    """
    Resolves hostname to IP addresses and verifies that every resolved IP is safe.
    Protects against SSRF and dual-homed DNS tricks.
    """
    cleaned_host = (hostname or "").strip().lower()
    if not cleaned_host:
        return False, [], "Nom d'hôte vide"

    # Allow local sandbox target if explicitly allowed
    if allow_local_lab and cleaned_host in LAB_HOSTS:
        return True, ["127.0.0.1"], "Hôte de laboratoire local autorisé"

    try:
        addr_infos = socket.getaddrinfo(cleaned_host, None)
    except socket.gaierror as e:
        return False, [], f"Échec de résolution DNS pour '{cleaned_host}': {e}"
    except Exception as e:
        return False, [], f"Erreur lors de la résolution de '{cleaned_host}': {e}"

    resolved_ips = []
    for info in addr_infos:
        sockaddr = info[4]
        ip = sockaddr[0]
        if ip not in resolved_ips:
            resolved_ips.append(ip)

    if not resolved_ips:
        return False, [], f"Aucune adresse IP résolue pour '{cleaned_host}'"

    # Validate every IP resolved
    for ip in resolved_ips:
        is_safe, reason = is_safe_ip(ip)
        if not is_safe:
            return False, resolved_ips, f"Échec de la validation de sécurité: {reason}"

    return True, resolved_ips, f"Validation réussie ({len(resolved_ips)} IP(s) publiques vérifiées)"

def validate_target_url(url: str, allow_local_lab: bool = False) -> Tuple[bool, Optional[str], Optional[str], str]:
    """
    Validates a full target URL:
    - Protocol must be http or https (no file://, gopher://, dict://, etc.)
    - Hostname must resolve to valid public IPs (or local lab if allow_local_lab=True)
    Returns: (is_valid, normalized_url, resolved_ip, message)
    """
    if not url or not isinstance(url, str):
        return False, None, None, "URL manquante"

    parsed = urllib.parse.urlparse(url.strip())
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        return False, None, None, f"Protocole non autorisé ('{scheme}'). Seuls HTTP et HTTPS sont acceptés."

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return False, None, None, "Nom d'hôte introuvable dans l'URL"

    # Anti-SSRF check
    is_safe, ips, msg = resolve_and_validate_hostname(hostname, allow_local_lab=allow_local_lab)
    if not is_safe:
        return False, None, None, msg

    pinned_ip = ips[0] if ips else None
    normalized = urllib.parse.urlunparse(parsed)
    return True, normalized, pinned_ip, "URL validée avec succès"
