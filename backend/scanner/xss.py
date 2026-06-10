import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

HEADERS = {"User-Agent": "VulnScanner/1.0"}

PAYLOADS = [
    "<script>alert('xss')</script>",
    "\"><script>alert('xss')</script>",
    "'><script>alert('xss')</script>",
    "<img src=x onerror=alert('xss')>",
    "\"><img src=x onerror=alert('xss')>",
]

# Attributes that indicate executable context
DANGEROUS_ATTRS = ["onerror", "onload", "onclick", "onmouseover", "onfocus", "onblur", "onkeyup"]


def is_reflected_in_executable_context(payload: str, html: str) -> bool:
    """
    Return True only if the payload is reflected in an executable HTML context:
    - Inside a <script> tag's text
    - Inside an event handler attribute (onerror, onload, etc.)
    NOT if it's just in a URL, meta tag, canonical, or og:url
    """
    soup = BeautifulSoup(html, "html.parser")

    # Check script tag bodies
    for script in soup.find_all("script"):
        if payload in (script.string or ""):
            return True

    # Check dangerous event handler attributes
    for tag in soup.find_all(True):
        for attr in DANGEROUS_ATTRS:
            val = tag.get(attr, "")
            if payload in val:
                return True

    # Check if raw unencoded payload appears outside of safe contexts
    # (meta, link, canonical tags often echo the URL safely)
    safe_tags = {"meta", "link", "script"}  # already handled above
    for tag in soup.find_all(True):
        if tag.name in safe_tags:
            continue
        # Check all attribute values
        for attr, val in tag.attrs.items():
            if isinstance(val, list):
                val = " ".join(val)
            if payload in val and attr not in ("href", "src", "action", "data"):
                return True

    return False


def check_xss(url: str) -> list:
    findings = []
    parsed = urlparse(url)

    # Only test URLs with query parameters
    if not parsed.query:
        return findings

    params = parse_qs(parsed.query)

    for param in params:
        for payload in PAYLOADS:
            test_params = dict(params)
            test_params[param] = [payload]
            test_query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=test_query))

            try:
                resp = requests.get(test_url, timeout=5, headers=HEADERS)

                if is_reflected_in_executable_context(payload, resp.text):
                    findings.append({
                        "vulnerability": "Reflected XSS",
                        "severity": "High",
                        "url": test_url,
                        "confidence": 92,
                        "payload": payload,
                    })
                    break  # One finding per parameter

            except requests.exceptions.RequestException as e:
                print(f"[XSS] Request failed: {e}")
                continue

    return findings