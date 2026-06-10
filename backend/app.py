from flask import Flask, request, jsonify
from flask_cors import CORS
from urllib.parse import urlparse
import uuid

from scanner.sqli import check_sqli
from scanner.xss import check_xss
from scanner.headers import check_headers
from scanner.crawler import crawl
from scanner.phishing import detect_phishing 
from scanner.browser_scan import browser_scan
from scanner.scam_detector import scam_bp

app = Flask(__name__)
CORS(app)
app.register_blueprint(scam_bp)

# ─────────────────────────────────────────────────────────────────────────────
# Metadata map: raw vulnerability name → frontend shape
# ─────────────────────────────────────────────────────────────────────────────
VULN_META = {
    "Possible SQL Injection": {
        "name": "SQL Injection",
        "category": "Injection",
        "severity": "High",
        "description": (
            "The application appears vulnerable to SQL injection. An attacker can "
            "manipulate backend database queries by injecting malicious SQL through "
            "user-supplied inputs, potentially exposing or corrupting all stored data."
        ),
        "details": (
            "Injected SQL payload via query parameter caused a DB error signature or "
            "a significant response length delta, indicating unsanitized input reaches "
            "the database layer."
        ),
        "mitigation": (
            "Use parameterized queries or prepared statements exclusively. Never "
            "concatenate user input into SQL strings. Apply an ORM, whitelist input "
            "validation, and configure database error messages to never reach clients."
        ),
    },
    "Reflected XSS": {
        "name": "Reflected Cross-Site Scripting (XSS)",
        "category": "XSS",
        "severity": "High",
        "description": (
            "User-supplied input is reflected back in the HTTP response without "
            "proper HTML encoding, allowing attackers to inject scripts that execute "
            "in victims' browsers — enabling session theft, keylogging, and phishing."
        ),
        "details": (
            "The injected XSS payload was found verbatim (unencoded) in the response "
            "body, confirming unsanitized reflection of user input into the HTML page."
        ),
        "mitigation": (
            "HTML-encode all user-supplied output. Use a strict Content-Security-Policy "
            "header. In JavaScript, always set content via textContent rather than "
            "innerHTML. Validate and sanitize all inputs server-side."
        ),
    },
    "Missing Content-Security-Policy": {
        "name": "Missing Content-Security-Policy Header",
        "category": "Security Headers",
        "severity": "Medium",
        "description": (
            "The Content-Security-Policy (CSP) header is absent. Without it, browsers "
            "allow inline scripts and arbitrary external resource loads, greatly "
            "increasing XSS attack surface."
        ),
        "details": "The Content-Security-Policy header was not present in the HTTP response.",
        "mitigation": (
            "Add a strict CSP: Content-Security-Policy: default-src 'self'; "
            "script-src 'self'; object-src 'none'; base-uri 'self'."
        ),
    },
    "Weak Content-Security-Policy": {
        "name": "Weak Content-Security-Policy Header",
        "category": "Security Headers",
        "severity": "Medium",
        "description": (
            "A Content-Security-Policy header is present but contains 'unsafe-inline' "
            "or 'unsafe-eval', which significantly weakens its protection against XSS."
        ),
        "details": "CSP header contains unsafe-inline or unsafe-eval directive.",
        "mitigation": (
            "Remove 'unsafe-inline' and 'unsafe-eval'. Use nonces or hashes for "
            "inline scripts instead."
        ),
    },
    "Missing X-Frame-Options": {
        "name": "Missing X-Frame-Options Header",
        "category": "Security Headers",
        "severity": "Medium",
        "description": (
            "The X-Frame-Options header is absent. This allows your pages to be "
            "embedded in iframes on malicious sites, enabling clickjacking attacks."
        ),
        "details": "The X-Frame-Options header was not present in the HTTP response.",
        "mitigation": "Add: X-Frame-Options: DENY (or SAMEORIGIN).",
    },
    "Missing Strict-Transport-Security": {
        "name": "Missing HSTS Header",
        "category": "Security Headers",
        "severity": "Medium",
        "description": (
            "The Strict-Transport-Security (HSTS) header is missing. Without it, "
            "browsers may downgrade HTTPS connections to HTTP, enabling MITM attacks."
        ),
        "details": "The Strict-Transport-Security header was not present in the HTTPS response.",
        "mitigation": (
            "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
        ),
    },
    "Weak Strict-Transport-Security": {
        "name": "Weak HSTS max-age",
        "category": "Security Headers",
        "severity": "Low",
        "description": "HSTS header is present but max-age is less than 1 day, offering minimal protection.",
        "details": "max-age value in HSTS header is below 86400 seconds.",
        "mitigation": "Set max-age to at least 31536000 (1 year) and add includeSubDomains.",
    },
    "Missing X-Content-Type-Options": {
        "name": "Missing X-Content-Type-Options Header",
        "category": "Security Headers",
        "severity": "Low",
        "description": (
            "Without X-Content-Type-Options: nosniff, browsers may MIME-sniff responses "
            "and execute them in unexpected ways."
        ),
        "details": "The X-Content-Type-Options header was not present in the HTTP response.",
        "mitigation": "Add: X-Content-Type-Options: nosniff",
    },
    "Missing Referrer-Policy": {
        "name": "Missing Referrer-Policy Header",
        "category": "Security Headers",
        "severity": "Low",
        "description": (
            "Without a Referrer-Policy, browsers send the full URL as the Referer header "
            "to third parties, potentially leaking sensitive path or query data."
        ),
        "details": "The Referrer-Policy header was not present in the HTTP response.",
        "mitigation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Missing Permissions-Policy": {
        "name": "Missing Permissions-Policy Header",
        "category": "Security Headers",
        "severity": "Low",
        "description": (
            "Without a Permissions-Policy header, the browser grants full access to "
            "powerful APIs (camera, microphone, geolocation) to the page and iframes."
        ),
        "details": "The Permissions-Policy header was not present in the HTTP response.",
        "mitigation": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
    },
    "Too Many External Links (Possible Ads/Phishing)": {
        "name": "Excessive External Links (Phishing Indicator)",
        "category": "Phishing Detection",
        "severity": "Medium",
        "description": (
            "The page contains an unusually high number of links to external domains "
            "at a high ratio, a pattern associated with ad-heavy or phishing pages."
        ),
        "details": "More than 20 external links detected with >50% external link ratio.",
        "mitigation": (
            "Audit and reduce external link count. Add rel='noopener noreferrer' "
            "to all external links."
        ),
    },
    "Suspicious External Script": {
        "name": "Suspicious External Script Loaded",
        "category": "Phishing Detection",
        "severity": "High",
        "description": (
            "The page loads JavaScript from an external domain not in the known-safe "
            "CDN/analytics whitelist. Compromised third-party scripts can steal data."
        ),
        "details": "An external script src pointing to an unknown third-party domain was detected.",
        "mitigation": (
            "Audit all third-party scripts. Add Subresource Integrity (SRI) hashes: "
            "<script src='...' integrity='sha384-...' crossorigin='anonymous'>"
        ),
    },
    "Suspicious Content Pattern": {
        "name": "Suspicious Phishing Keywords Detected",
        "category": "Phishing Detection",
        "severity": "Medium",
        "description": (
            "The page contains multiple keywords strongly associated with phishing "
            "or social engineering attacks."
        ),
        "details": "Two or more phishing-associated keywords were found in page content.",
        "mitigation": (
            "Review and remove suspicious language. Implement server-side content "
            "moderation for user-generated content."
        ),
    },
    "Redirect Detected": {
        "name": "Cross-Domain Redirect Chain Detected",
        "category": "Phishing Detection",
        "severity": "Medium",
        "description": (
            "The server redirected through multiple domains before delivering the final "
            "page — a technique used in phishing to mask the final destination."
        ),
        "details": "HTTP response history contained redirects crossing domain boundaries.",
        "mitigation": (
            "Ensure all redirects are intentional and stay within trusted domains. "
            "Log and monitor all redirect chains."
        ),
    },
    "External Script (Ad/Tracking)": {
        "name": "External Tracking/Ad Script Detected",
        "category": "Browser Analysis",
        "severity": "Medium",
        "description": (
            "A JavaScript resource from an unknown third-party domain was detected after "
            "full browser rendering. These scripts may fingerprint users or serve malicious ads."
        ),
        "details": (
            "Selenium-rendered page revealed external script src attributes "
            "pointing to non-whitelisted third-party domains."
        ),
        "mitigation": (
            "Audit all third-party scripts. Use CSP to allowlist only trusted origins. "
            "Add SRI checks for all third-party scripts."
        ),
    },
    "Popup/Redirect Behavior": {
        "name": "Popup or Forced Redirect Behavior",
        "category": "Browser Analysis",
        "severity": "High",
        "description": (
            "The page triggered a popup or opened additional browser tabs upon loading — "
            "a strong indicator of malicious ad injection or phishing redirects."
        ),
        "details": "Multiple browser window handles detected after page load via Selenium.",
        "mitigation": (
            "Audit all JavaScript for window.open() calls. Implement a strict CSP. "
            "Report to Google Safe Browsing if confirmed malicious."
        ),
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _confidence_to_severity(base_severity: str, confidence: float) -> str:
    """
    Upgrade or downgrade severity based on confidence.
    High confidence + High base → Critical.
    Low confidence + High base → Medium.
    """
    order = ["Low", "Medium", "High", "Critical"]
    idx = order.index(base_severity) if base_severity in order else 1

    if confidence >= 0.90 and idx >= 2:    # High/Critical with ≥90% conf → Critical
        return "Critical"
    if confidence < 0.50 and idx >= 2:     # High/Critical with <50% conf → Medium
        return "Medium"
    return base_severity


def build_vulnerability(finding: dict) -> dict:
    raw_key = finding.get("vulnerability", "Unknown")

    meta = VULN_META.get(raw_key)
    if not meta:
        for key in VULN_META:
            if key.lower() in raw_key.lower() or raw_key.lower() in key.lower():
                meta = VULN_META[key]
                break

    if not meta:
        meta = {
            "name": raw_key,
            "category": "General",
            "severity": finding.get("severity", "Medium"),
            "description": "A potential security issue was detected during the scan.",
            "details": "No additional technical details available for this finding.",
            "mitigation": "Review the affected endpoint and apply appropriate security controls.",
        }

    # Normalize confidence: backend sends 0–100, frontend expects 0.0–1.0
    raw_conf = finding.get("confidence", 70)
    confidence = round(raw_conf / 100 if raw_conf > 1 else float(raw_conf), 2)

    base_severity = finding.get("severity", meta.get("severity", "Medium"))
    final_severity = _confidence_to_severity(base_severity, confidence)

    return {
        "id": str(uuid.uuid4()),
        "name": meta["name"],
        "category": meta["category"],
        "severity": final_severity,
        "confidence": confidence,
        "affectedUrl": finding.get("url", ""),
        "description": meta["description"],
        "details": meta["details"],
        "mitigation": meta["mitigation"],
        # Pass param through so frontend can show which input was vulnerable
        "param": finding.get("param", ""),
    }


def deduplicate(findings: list) -> list:
    """
    Deduplicate on (category, param, affected-domain).
    This collapses SQLi/XSS found on the same param across multiple URLs
    into one finding, while keeping genuinely distinct findings separate.
    """
    seen: set[tuple] = set()
    unique: list[dict] = []

    for f in findings:
        affected_domain = urlparse(f["affectedUrl"]).netloc
        key = (f["category"], f.get("param", ""), affected_domain)

        # For header/phishing findings key on (category, name, domain)
        if f["category"] in ("Security Headers", "Phishing Detection", "Browser Analysis"):
            key = (f["category"], f["name"], affected_domain)

        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/scan", methods=["POST"])
def scan():
    data        = request.get_json()
    target_url  = data.get("url", "").strip()
    scan_type   = data.get("type", "full")    # full | quick | stealth
    scan_depth  = data.get("depth", "normal") # shallow | normal | deep

    if not target_url:
        return jsonify({"error": "No URL provided", "results": []}), 400

    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    # ── Crawl depth by scan options ───────────────────────────────────────
    max_pages = {"shallow": 3, "normal": 10, "deep": 25}.get(scan_depth, 10)

    # ── Which scanners to run per scan type ───────────────────────────────
    all_scanners = [
        ("SQLi",     check_sqli),
        ("XSS",      check_xss),
        ("Headers",  check_headers),
        ("Phishing", detect_phishing),
        ("Browser",  browser_scan),
    ]
    quick_scanners = [("Headers", check_headers), ("Phishing", detect_phishing)]
    active_scanners = quick_scanners if scan_type == "quick" else all_scanners

    raw_findings: list[dict] = []
    scanned_urls: list[str] = []
    errors: list[str] = []

    try:
        urls = crawl(target_url, max_pages=max_pages)
    except Exception as e:
        errors.append(f"Crawler failed: {e}")
        urls = [target_url]

    for url in urls:
        scanned_urls.append(url)
        for scanner_name, scanner_fn in active_scanners:
            try:
                findings = scanner_fn(url)
                raw_findings.extend(findings)
            except Exception as e:
                errors.append(f"{scanner_name} scanner failed on {url}: {e}")

    results = deduplicate([build_vulnerability(f) for f in raw_findings])

    # Sort by severity
    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    results.sort(key=lambda v: sev_order.get(v["severity"], 4))

    return jsonify({
        "target":             target_url,
        "total_urls_scanned": len(scanned_urls),
        "scan_type":          scan_type,
        "scan_depth":         scan_depth,
        "results":            results,
        "errors":             errors,
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "scanners": ["sqli", "xss", "headers", "phishing", "browser"],
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)