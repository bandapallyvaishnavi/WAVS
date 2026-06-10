from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import WebDriverException
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup
from urllib.parse import urlparse

# Trusted domains — never flag these as external threats
TRUSTED_DOMAINS = {
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
    "seal.godaddy.com",
    "seal.comodo.com",
    "seal.digicert.com",
    "www.recaptcha.net",
    "www.gstatic.com",
    "assets.adobedtm.com",
}


def is_trusted(src: str) -> bool:
    domain = urlparse(src).netloc.lower()
    return any(domain == t or domain.endswith("." + t) for t in TRUSTED_DOMAINS)


def _make_driver() -> webdriver.Chrome:
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--window-size=1920,1080")
    return webdriver.Chrome(
        service=Service(ChromeDriverManager().install()),
        options=options,
    )


def browser_scan(url: str) -> list:
    findings = []
    driver = None

    try:
        driver = _make_driver()
        driver.set_page_load_timeout(15)
        driver.get(url)
        driver.implicitly_wait(5)

        html = driver.page_source
        soup = BeautifulSoup(html, "html.parser")
        page_domain = urlparse(url).netloc

        # ── Unknown external scripts only (not CDNs/trusted services) ─────────
        seen = set()
        for script in soup.find_all("script", src=True):
            src = script["src"]
            if src in seen:
                continue
            seen.add(src)

            script_domain = urlparse(src).netloc
            same_domain   = script_domain == page_domain or not script_domain

            if not same_domain and not is_trusted(src):
                findings.append({
                    "vulnerability": "External Script (Ad/Tracking)",
                    "severity": "Medium",
                    "url": src,
                    "confidence": 85,
                })

        # ── Popup / new tab detection ──────────────────────────────────────────
        if len(driver.window_handles) > 1:
            findings.append({
                "vulnerability": "Popup/Redirect Behavior",
                "severity": "High",
                "url": url,
                "confidence": 95,
            })

    except WebDriverException as e:
        print(f"[Browser] WebDriver error on {url}: {e}")
    except Exception as e:
        print(f"[Browser] Unexpected error on {url}: {e}")
    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass

    return findings