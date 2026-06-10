import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

HEADERS = {"User-Agent": "VulnScanner/1.0"}


def normalize_url(url: str) -> str:
    """Normalize URL to avoid scanning same page twice (trailing slash, etc.)."""
    parsed = urlparse(url)
    # Remove trailing slash from path (except root)
    path = parsed.path.rstrip("/") or "/"
    return parsed._replace(path=path, fragment="", query="").geturl()


def is_valid_url(url: str, base_domain: str) -> bool:
    """Return True only for clean, same-domain URLs worth scanning."""
    try:
        parsed = urlparse(url)
    except Exception:
        return False

    # Must be same domain
    if parsed.netloc != base_domain:
        return False

    # Reject Windows path separators leaking into URLs
    if "\\" in url or "%5C" in url.upper():
        return False

    # Reject path traversal attempts
    if ".." in parsed.path:
        return False

    # Reject non-HTTP schemes
    if parsed.scheme not in ("http", "https"):
        return False

    # Skip static files — no security headers to check
    skip_extensions = (
        ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".svg",
        ".ico", ".css", ".js", ".woff", ".woff2", ".ttf",
        ".zip", ".rar", ".doc", ".docx", ".xls", ".xlsx",
    )
    if any(parsed.path.lower().endswith(ext) for ext in skip_extensions):
        return False

    return True


def crawl(base_url: str, max_pages: int = 5, timeout_per_page: int = 4) -> list:
    """
    Crawl pages within the same domain.
    Returns deduplicated, clean URLs only.
    """
    base_domain = urlparse(base_url).netloc
    visited     = set()
    to_visit    = [normalize_url(base_url)]

    while to_visit and len(visited) < max_pages:
        url = to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)

        try:
            resp = requests.get(url, timeout=timeout_per_page, headers=HEADERS, allow_redirects=True)
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, "html.parser")

            for link in soup.find_all("a", href=True):
                full = urljoin(base_url, link["href"])
                clean = normalize_url(full)
                if is_valid_url(clean, base_domain) and clean not in visited:
                    to_visit.append(clean)

        except requests.exceptions.Timeout:
            print(f"[Crawler] Timeout — {url}")
        except requests.exceptions.RequestException as e:
            print(f"[Crawler] Error — {url}: {e}")
        except Exception as e:
            print(f"[Crawler] Unexpected — {url}: {e}")

    # Always include base URL
    norm_base = normalize_url(base_url)
    if norm_base not in visited:
        visited.add(norm_base)

    print(f"[Crawler] Found {len(visited)} clean URL(s)")
    return list(visited)