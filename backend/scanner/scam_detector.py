"""
scam_detector.py
Flask blueprint that powers the AI Scam Detector page.

Install extra deps:
    pip install python-whois requests pillow selenium webdriver-manager

Environment variables (add to .env or export before running):
    GOOGLE_SAFE_BROWSING_API_KEY=<your key from https://developers.google.com/safe-browsing>
"""

import os
import ssl
import socket
import base64
import datetime
import requests
import whois                          # pip install python-whois
from io import BytesIO
from urllib.parse import urlparse
from flask import Blueprint, request, jsonify

# Optional — screenshot via Selenium (same driver used by browser_scan.py)
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from webdriver_manager.chrome import ChromeDriverManager
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

scam_bp = Blueprint("scam", __name__)

SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
HEADERS = {"User-Agent": "VulnScanner/1.0"}


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _hostname(url: str) -> str:
    return urlparse(url).hostname or url


def _check_ssl(url: str) -> dict:
    """
    Verify SSL certificate and return expiry info.
    Returns status: pass | warn | fail
    """
    host = _hostname(url)
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(8)
            s.connect((host, 443))
            cert = s.getpeercert()

        not_after = datetime.datetime.strptime(
            cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
        )
        days_left = (not_after - datetime.datetime.utcnow()).days

        if days_left <= 0:
            return {"status": "fail", "detail": "Certificate has EXPIRED", "days_left": days_left}
        if days_left <= 14:
            return {"status": "warn", "detail": f"Expires in {days_left} days — renew soon", "days_left": days_left}

        issuer = dict(x[0] for x in cert.get("issuer", []))
        org = issuer.get("organizationName", "Unknown CA")
        return {
            "status": "pass",
            "detail": f"Valid · expires in {days_left}d · issued by {org}",
            "days_left": days_left,
        }

    except ssl.SSLCertVerificationError as e:
        return {"status": "fail", "detail": f"SSL verification failed: {e.reason}"}
    except ssl.SSLError as e:
        return {"status": "fail", "detail": f"SSL error: {str(e)[:80]}"}
    except (socket.timeout, socket.gaierror) as e:
        return {"status": "warn", "detail": f"Could not reach host: {str(e)[:60]}"}
    except Exception as e:
        return {"status": "warn", "detail": f"SSL check error: {str(e)[:80]}"}


def _check_whois(url: str) -> dict:
    """
    Look up domain registration age via WHOIS.
    Returns status: pass | warn | fail
    """
    host = _hostname(url)
    # Strip subdomains for cleaner WHOIS results
    parts = host.split(".")
    domain = ".".join(parts[-2:]) if len(parts) > 2 else host

    try:
        w = whois.whois(domain)
        created = w.creation_date

        if isinstance(created, list):
            created = created[0]

        if not created:
            return {"status": "warn", "detail": "No creation date in WHOIS record"}

        age_days = (datetime.datetime.now() - created).days
        age_years = age_days / 365

        registrar = w.registrar or "Unknown"

        if age_days < 30:
            return {
                "status": "fail",
                "detail": f"Domain created {age_days}d ago — very new, high risk",
                "age_days": age_days,
                "registrar": registrar,
            }
        if age_days < 180:
            return {
                "status": "warn",
                "detail": f"Domain is only {age_days}d old — treat with caution",
                "age_days": age_days,
                "registrar": registrar,
            }

        return {
            "status": "pass",
            "detail": f"Registered {age_years:.1f} years ago via {registrar}",
            "age_days": age_days,
            "registrar": registrar,
        }

    except whois.parser.PywhoisError:
        return {"status": "warn", "detail": "WHOIS lookup failed — domain may be private"}
    except Exception as e:
        return {"status": "warn", "detail": f"WHOIS error: {str(e)[:80]}"}


def _check_redirects(url: str) -> dict:
    """
    Follow redirect chain and report hops.
    """
    try:
        resp = requests.get(url, timeout=8, headers=HEADERS, allow_redirects=True)
        hops = resp.history

        if not hops:
            return {"status": "pass", "detail": "No redirects — direct response", "hops": 0}

        domains = [urlparse(r.url).netloc for r in hops]
        domains.append(urlparse(resp.url).netloc)
        unique_domains = list(dict.fromkeys(domains))

        cross_domain = len(set(domains)) > 1

        if len(hops) >= 3 and cross_domain:
            return {
                "status": "fail",
                "detail": f"{len(hops)} redirects across {len(set(domains))} domains — suspicious chain",
                "hops": len(hops),
                "chain": unique_domains,
            }
        if len(hops) >= 2 or cross_domain:
            return {
                "status": "warn",
                "detail": f"{len(hops)} redirect(s) — {' → '.join(unique_domains[:3])}",
                "hops": len(hops),
                "chain": unique_domains,
            }

        return {
            "status": "pass",
            "detail": f"HTTP→HTTPS redirect only — normal",
            "hops": len(hops),
        }

    except requests.exceptions.TooManyRedirects:
        return {"status": "fail", "detail": "Redirect loop detected (>30 hops)"}
    except requests.exceptions.RequestException as e:
        return {"status": "warn", "detail": f"Could not follow redirects: {str(e)[:60]}"}


def _check_safe_browsing(url: str) -> dict:
    """
    Query Google Safe Browsing API v4.
    Requires GOOGLE_SAFE_BROWSING_API_KEY env var.
    """
    if not SAFE_BROWSING_KEY:
        return {
            "status": "warn",
            "detail": "GOOGLE_SAFE_BROWSING_API_KEY not set — skipped",
        }

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_KEY}"
    body = {
        "client": {"clientId": "vulnscanner", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes":  ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        resp = requests.post(endpoint, json=body, timeout=8)
        data = resp.json()

        if data.get("matches"):
            types = list({m["threatType"] for m in data["matches"]})
            return {
                "status": "fail",
                "detail": f"FLAGGED by Google Safe Browsing: {', '.join(types)}",
                "threat_types": types,
            }

        return {"status": "pass", "detail": "Not flagged by Google Safe Browsing"}

    except Exception as e:
        return {"status": "warn", "detail": f"Safe Browsing API error: {str(e)[:80]}"}


def _check_phishing_patterns(url: str) -> dict:
    """
    Heuristic checks: suspicious TLDs, brand impersonation, IP addresses, etc.
    """
    host = _hostname(url) or ""
    flags = []

    SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click", ".loan"}
    IMPERSONATION_KEYWORDS = [
        "paypal", "apple", "google", "microsoft", "amazon", "facebook",
        "netflix", "instagram", "whatsapp", "bank", "secure", "login",
        "verify", "account", "update", "support",
    ]

    # IP address as hostname
    try:
        socket.inet_aton(host)
        flags.append("IP address used instead of domain name")
    except socket.error:
        pass

    # Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            flags.append(f"High-risk TLD: {tld}")
            break

    # Brand impersonation in subdomain
    parts = host.split(".")
    if len(parts) > 2:
        subdomain = ".".join(parts[:-2])
        for brand in IMPERSONATION_KEYWORDS:
            if brand in subdomain.lower():
                flags.append(f"Brand name '{brand}' in subdomain — possible typosquat")
                break

    # Excessive hyphens
    if host.count("-") >= 3:
        flags.append(f"Excessive hyphens in domain ({host.count('-')} hyphens)")

    # Very long domain
    if len(host) > 40:
        flags.append(f"Unusually long domain ({len(host)} chars)")

    if not flags:
        return {"status": "pass", "detail": "No phishing patterns detected", "flags": []}
    if len(flags) >= 2:
        return {"status": "fail", "detail": f"{len(flags)} phishing indicators: {flags[0]}", "flags": flags}
    return {"status": "warn", "detail": flags[0], "flags": flags}


def _take_screenshot(url: str) -> dict:
    """
    Take a full-page screenshot via headless Chrome and return base64 PNG.
    """
    if not SELENIUM_AVAILABLE:
        return {"status": "warn", "detail": "Selenium not installed", "image": None}

    driver = None
    try:
        options = Options()
        options.add_argument("--headless")
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--window-size=1280,800")

        driver = webdriver.Chrome(
            service=Service(ChromeDriverManager().install()),
            options=options,
        )
        driver.set_page_load_timeout(15)
        driver.get(url)
        driver.implicitly_wait(3)

        png = driver.get_screenshot_as_png()
        b64 = base64.b64encode(png).decode("utf-8")

        return {"status": "pass", "detail": "Screenshot captured", "image": b64}

    except Exception as e:
        return {"status": "warn", "detail": f"Screenshot failed: {str(e)[:80]}", "image": None}
    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass


def _compute_score(checks: dict) -> int:
    """
    Compute overall reputation score (0–100) from individual check results.
    """
    weights = {
        "ssl":            25,
        "safe_browsing":  30,
        "whois":          15,
        "redirects":      10,
        "phishing":       20,
    }
    score = 100
    for key, weight in weights.items():
        result = checks.get(key, {})
        status = result.get("status", "pass")
        if status == "fail":
            score -= weight
        elif status == "warn":
            score -= weight // 2

    return max(0, min(100, score))


# ─── Routes ──────────────────────────────────────────────────────────────────

@scam_bp.route("/scam-check", methods=["POST"])
def scam_check():
    """
    Run all scam detector checks against a URL.
    Body: { "url": "https://example.com" }
    Response: { checks: {...}, score: int, screenshot: str|null }
    """
    data = request.get_json()
    url  = (data or {}).get("url", "").strip()

    if not url:
        return jsonify({"error": "No URL provided"}), 400
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # Run all checks (screenshot is async-ish — runs last)
    checks = {
        "ssl":          _check_ssl(url),
        "whois":        _check_whois(url),
        "redirects":    _check_redirects(url),
        "safe_browsing": _check_safe_browsing(url),
        "phishing":     _check_phishing_patterns(url),
    }

    score      = _compute_score(checks)
    screenshot = _take_screenshot(url)

    return jsonify({
        "url":        url,
        "score":      score,
        "checks":     checks,
        "screenshot": screenshot,
        "checked_at": datetime.datetime.utcnow().isoformat() + "Z",
    })


@scam_bp.route("/scam-check/screenshot", methods=["POST"])
def screenshot_only():
    """Lightweight endpoint — screenshot only, no checks. Used for fast preview."""
    data = request.get_json()
    url  = (data or {}).get("url", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    return jsonify(_take_screenshot(url))