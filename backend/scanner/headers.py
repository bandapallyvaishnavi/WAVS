import requests

def check_headers(url):
    findings = []

    try:
        res = requests.get(url, timeout=3)
        headers = res.headers

        required_headers = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "Strict-Transport-Security",
            "X-Content-Type-Options"
        ]

        for h in required_headers:
            if h not in headers:
                findings.append({
                    "vulnerability": f"Missing {h}",
                    "severity": "Medium",
                    "url": url,
                    "confidence": 70
                })

    except:
        pass

    return findings