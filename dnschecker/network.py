"""Generic network labels and privacy-safe detection of the current egress organisation."""

import ipaddress
import urllib.request

from . import owners

NETWORK_TYPES = (("office", "Офис"), ("home", "Дом"), ("vpn", "VPN"), ("other", "Другое"))
TYPE_LABELS = dict(NETWORK_TYPES)
TYPE_KEYS = {label: key for key, label in NETWORK_TYPES}
PUBLIC_IP_URL = "https://api.ipify.org"


def type_label(key):
    return TYPE_LABELS.get(key, TYPE_LABELS["other"])


def type_key(label):
    return TYPE_KEYS.get(label, "other")


def _fetch_public_ip(url, timeout):
    request = urllib.request.Request(url, headers={"User-Agent": "DNS-Checker"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        text = response.read(64).decode("ascii", errors="ignore").strip()
    return str(ipaddress.ip_address(text))  # kept only in local memory


def detect_org(timeout=3, ip_fetch=None, rdap_fetch=None):
    """
    Return {"org", "country"} without returning, logging, or caching the public IP.
    Any failure simply means that the network organisation is unknown.
    """
    ip_fetch = ip_fetch or _fetch_public_ip
    rdap_fetch = rdap_fetch or owners._fetch_rdap
    try:
        public_ip = ip_fetch(PUBLIC_IP_URL, timeout)
        for source in owners.RDAP_SOURCES:
            try:
                data = rdap_fetch(source.format(ip=public_ip), timeout)
                org = owners.rdap_org(data) or data.get("name", "") or ""
                return {"org": org, "country": data.get("country", "") or ""}
            except Exception:
                continue
    except Exception:
        pass
    return {"org": "", "country": ""}


def org_text(info):
    """Short report-safe text; never includes the detected address itself."""
    info = info or {}
    org, country = info.get("org", ""), info.get("country", "")
    return f"{org} ({country})" if org and country else org
