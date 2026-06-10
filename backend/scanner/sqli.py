import requests
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

HEADERS = {"User-Agent": "VulnScanner/1.0"}

# These strings only appear in real database error responses
DB_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql_",
    "warning: mysqli_",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "ora-01756",
    "ora-00907",
    "pg_query():",
    "pg_exec():",
    "sqlite3.operationalerror",
    "sqliteexception",
    "microsoft ole db provider for sql server",
    "odbc microsoft access driver",
    "[microsoft][odbc sql server driver]",
    "supplied argument is not a valid mysql",
    "mysql_num_rows()",
    "mysql_fetch_array()",
    "sql server",
    "syntax error or access violation",
    "division by zero",        # common SQL error leak
    "unknown column",
    "table or view does not exist",
]

# Only test time-based and error-based payloads — NOT length-based
PAYLOADS = [
    "'",                        # basic quote — triggers syntax errors
    "''",                       # escaped quote
    "' OR '1'='1' --",
    "\" OR \"1\"=\"1\" --",
    "'; SELECT SLEEP(0); --",   # won't actually sleep but triggers parse errors
    "1 AND 1=CONVERT(int, @@version)--",  # MSSQL error-based
]


def check_sqli(url: str) -> list:
    findings = []
    parsed = urlparse(url)

    # Only test URLs that have query parameters — others are not injectable via URL
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
                resp_lower = resp.text.lower()

                # ONLY flag if a real DB error signature is found
                matched_sig = next((sig for sig in DB_ERROR_SIGNATURES if sig in resp_lower), None)

                if matched_sig:
                    findings.append({
                        "vulnerability": "Possible SQL Injection",
                        "severity": "High",
                        "url": test_url,
                        "confidence": 90,
                        "payload": payload,
                        "evidence": matched_sig,
                    })
                    break  # One finding per parameter is enough

            except requests.exceptions.RequestException as e:
                print(f"[SQLi] Request failed: {e}")
                continue

    return findings