import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

HEADERS = {"User-Agent": "VulnScanner/1.0"}

# Trusted external script domains — do NOT flag these
TRUSTED_SCRIPT_DOMAINS = {
    "cdn.jsdelivr.net",
    "code.jquery.com",
    "cdnjs.cloudflare.com",
    "ajax.googleapis.com",
    "ajax.microsoft.com",
    "stackpath.bootstrapcdn.com",
    "maxcdn.bootstrapcdn.com",
    "unpkg.com",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "www.google-analytics.com",
    "www.googletagmanager.com",
    "connect.facebook.net",
    "platform.twitter.com",
    "js.stripe.com",
    "js.paypal.com",
    "seal.godaddy.com",          # trust seal — not malicious
    "seal.comodo.com",
    "seal.digicert.com",
    "seal.verisign.com",
    "assets.adobedtm.com",
    "www.recaptcha.net",
    "www.gstatic.com",
}

# Only flag these if they are genuinely unknown/suspicious external scripts
# i.e., random domains that are not CDNs or known services
def is_suspicious_script_domain(src: str, page_domain: str) -> bool:
    parsed = urlparse(src)
    domain = parsed.netloc.lower()

    # Same domain — fine
    if domain == page_domain or not domain:
        return False

    # Known trusted CDN / service — fine
    if any(domain == t or domain.endswith("." + t) for t in TRUSTED_SCRIPT_DOMAINS):
        return False

    # Has a proper TLD and looks like a random/unknown domain — suspicious
    return True


def detect_phishing(url: str) -> list:
    findings = []

    try:
        res = requests.get(url, timeout=5, headers=HEADERS, allow_redirects=True)
        soup = BeautifulSoup(res.text, "html.parser")
        domain = urlparse(url).netloc

        # ── 1. Unknown external scripts only ──────────────────────────────────
        seen_srcs = set()
        for script in soup.find_all("script", src=True):
            src = script["src"]
            if src in seen_srcs:
                continue
            seen_srcs.add(src)

            if is_suspicious_script_domain(src, domain):
                findings.append({
                    "vulnerability": "Suspicious External Script",
                    "severity": "High",
                    "url": src,
                    "confidence": 75,
                })

        # ── 2. Redirect chain ────────────────────────────────────────────────
        # Only flag if redirected to a DIFFERENT domain (not just http→https)
        if res.history:
            final_domain   = urlparse(res.url).netloc
            initial_domain = urlparse(url).netloc
            if final_domain != initial_domain:
                findings.append({
                    "vulnerability": "Redirect Detected",
                    "severity": "Medium",
                    "url": url,
                    "confidence": 80,
                })

        # ── 3. Excessive external links ───────────────────────────────────────
        # Raise the threshold — normal sites link externally often
        external_links = sum(
            1 for a in soup.find_all("a", href=True)
            if a["href"].startswith("http") and domain not in a["href"]
        )
        if external_links > 30:  # raised from 10 → 30
            findings.append({
                "vulnerability": "Too Many External Links (Possible Ads/Phishing)",
                "severity": "Medium",
                "url": url,
                "confidence": min(50 + external_links, 85),
            })

        # NOTE: Removed "Suspicious Content Pattern" check entirely —
        # Words like "download", "click here" appear on every legitimate site.

    except requests.exceptions.RequestException as e:
        print(f"[Phishing] Request failed for {url}: {e}")
    except Exception as e:
        print(f"[Phishing] Unexpected error for {url}: {e}")

    return findings