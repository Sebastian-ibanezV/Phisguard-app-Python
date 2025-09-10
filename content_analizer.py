import logging
import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import tldextract
from functools import lru_cache
import time
import random
import joblib  
from joblib import Memory
import re
import math

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(message)s")

# Cache persistente en disco
cache_dir = './cache'
memory = Memory(cache_dir, verbose=0)

# Selenium driver global
selenium_driver = None

def get_selenium_driver():
    global selenium_driver
    if selenium_driver is None:
        options = Options()
        options.add_argument("--headless")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-gpu")
        selenium_driver = webdriver.Chrome(options=options)
    return selenium_driver

# =======================
# Configuración / Constantes
# =======================

ECOMMERCE_KEYWORDS = [
    "cart", "checkout", "buy", "order", "shipping", "sale", "discount",
    "promo", "free delivery", "offer", "payment"
]

NEWS_SOCIAL_PATTERNS = [
    "wikipedia.org", "facebook.com", "instagram.com", "twitter.com", 
    "linkedin.com", "youtube.com", "tiktok.com", "reddit.com",
    "bbc.", "cnn.", "nytimes.", "forbes.", "reuters.", 
    "guide", "tutorial", "how to", "avoid", "identify", "scam alert", "warning"
]

EDUCATIONAL_CONTEXT = [
    "how to", "guide to", "avoid", "detect", "spot", 
    "identify", "warning", "alert", "beware", "scam guide", "fake guide"
]

# Plataformas oficiales donde las marcas distribuyen apps/productos
WHITELIST_PLATFORMS = {
    "play.google.com": "official_distribution",
    "apps.apple.com": "official_distribution",
    "amazon.com": "official_distribution",
    "microsoft.com": "official_distribution"
}

# Retailer keywords para heurística de "retailer autorizado"
RETAILER_KEYWORDS = ["footwear", "sportinggoods", "footlocker", "amazon", "zalando", "finishline", "jdports", "asos"]

# TLDs comúnmente usados en phishing
SUSPICIOUS_TLDS = {"top", "tk", "xyz", "cc", "pw"}

# Pesos para scoring
SCORE_WEIGHTS = {
    "keyword": 0.2,
    "ecommerce": 0.3,
    "forms": 0.2,
    "images": 0.1,
    "brand_mismatch": 0.4,
    "educational_penalty": -0.2,
    "suspicious_tld": 0.3,
    "whitelist_override": 0.1,
    "exact_brand_match": 0.5,
    "subdomain_brand": 0.3,
    "retailer_keyword": 0.2
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"
]

# Errores comunes para manejo
ERROR_MESSAGES = {
    "access_denied": "access denied",
    "site_unreachable": "this site can’t be reached"
}

# =======================
# Funciones auxiliares
# =======================

@memory.cache
def get_html(url, use_selenium=False, timeout=10):
    """Obtiene HTML de una URL (requests -> selenium fallback), cacheado en disco. Retorna HTML o mensaje de error."""
    try:
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        r = requests.get(url, headers=headers, timeout=timeout)
        if r.status_code == 200 and r.text.strip():
            return r.text
        elif r.status_code == 403:
            return f"ERROR: {ERROR_MESSAGES['access_denied']}"
        logger.debug(f"Requests falló para {url} (status: {r.status_code}), intentando Selenium...")
        use_selenium = True
    except requests.exceptions.ConnectionError:
        return f"ERROR: {ERROR_MESSAGES['site_unreachable']}"
    except Exception as e:
        logger.debug(f"Requests falló para {url}: {e}, intentando Selenium...")
        use_selenium = True

    if use_selenium:
        try:
            driver = get_selenium_driver()
            driver.set_page_load_timeout(timeout)
            driver.get(url)
            time.sleep(random.uniform(1, 3))  # Espera variable para JS (puede ajustarse con WebDriverWait si se busca elementos específicos)
            html = driver.page_source
            if html.strip():
                return html
            return f"ERROR: {ERROR_MESSAGES['site_unreachable']}"
        except Exception as e:
            logger.debug(f"Selenium falló para {url}: {e}")
            return f"ERROR: {ERROR_MESSAGES['site_unreachable']}"

    return None


def is_brand_domain(url, brand):
    """Evalúa si el dominio contiene la marca."""
    ext = tldextract.extract(url)
    domain = ext.domain.lower()
    return brand.lower() in domain


def is_exact_brand_match(url, brand):
    """Evalúa si el dominio coincide exactamente con la marca."""
    ext = tldextract.extract(url)
    domain = ext.domain.lower()
    return domain == brand.lower()


def is_brand_subdomain(url, brand):
    """Evalúa si es subdominio de la marca."""
    ext = tldextract.extract(url)
    subdomain = ext.subdomain.lower()
    return brand.lower() in subdomain


def is_retailer_domain(url):
    """Evalúa si el dominio contiene retailer keywords."""
    ext = tldextract.extract(url)
    domain = ext.domain.lower()
    return any(kw in domain for kw in RETAILER_KEYWORDS)


def is_informational_site(url):
    """Detecta sitios de noticias/redes sociales/educativos."""
    for pattern in NEWS_SOCIAL_PATTERNS:
        if pattern in url.lower():
            return True
    return False


def is_whitelisted_platform(url):
    """Verifica si la URL pertenece a una plataforma oficial o retailer autorizado."""
    domain = urlparse(url).netloc.lower()
    if any(whitelisted in domain for whitelisted in WHITELIST_PLATFORMS):
        return True
    if is_retailer_domain(url):
        return True  # Heurística de retailer autorizado
    return False


def is_suspicious_tld(url):
    """Evalúa si el TLD es sospechoso."""
    ext = tldextract.extract(url)
    return ext.suffix in SUSPICIOUS_TLDS


def analyze_content(html: str, keyword: str, base_url: str):
    """Analiza el contenido y devuelve métricas y score."""
    if not html:
        return None

    if html.startswith("ERROR:"):
        # Manejo de errores en analyze (pero ya manejado en process_url)
        return {"error": html.replace("ERROR: ", "")}

    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text(separator=" ", strip=True).lower()
    
    # Snippet alrededor del keyword
    idx = text.find(keyword.lower())
    snippet = text[max(0, idx-100): idx+400] if idx != -1 else text[:500]

    # Conteos con regex para palabras completas
    keyword_count = len(re.findall(rf"\b{re.escape(keyword.lower())}\b", text))
    ecommerce_count = sum(len(re.findall(rf"\b{re.escape(k)}\b", text)) for k in ECOMMERCE_KEYWORDS)
    forms_count = len(soup.find_all("form"))
    buttons_count = len(soup.find_all("button"))
    images_count = len(soup.find_all("img"))

    # Flags
    exact_brand_match = is_exact_brand_match(base_url, keyword)
    brand_subdomain = is_brand_subdomain(base_url, keyword)
    brand_domain = is_brand_domain(base_url, keyword)
    informational = is_informational_site(base_url)
    whitelisted = is_whitelisted_platform(base_url)
    suspicious_tld = is_suspicious_tld(base_url)

    # Score base con escala logarítmica para keyword_count
    score = 0.0
    score += min(math.log(1 + keyword_count) / math.log(11), SCORE_WEIGHTS["keyword"])  # Escala a max weight en ~10 menciones
    score += min(ecommerce_count / 10, SCORE_WEIGHTS["ecommerce"])
    score += min(forms_count / 5, SCORE_WEIGHTS["forms"])
    score += min(images_count / 20, SCORE_WEIGHTS["images"])

    # Rebalanceo de score
    if exact_brand_match:
        score += SCORE_WEIGHTS["exact_brand_match"]
    if brand_subdomain:
        score += SCORE_WEIGHTS["subdomain_brand"]
    if is_retailer_domain(base_url):
        score += SCORE_WEIGHTS["retailer_keyword"]

    # Ajustes
    if keyword_count > 0 and not brand_domain and not informational:
        score += SCORE_WEIGHTS["brand_mismatch"]

    if informational:
        score = min(score, 0.3)

    if "scam" in text or "fake" in text:
        if any(ctx in text for ctx in EDUCATIONAL_CONTEXT):
            score += SCORE_WEIGHTS["educational_penalty"]

    if suspicious_tld:
        score += SCORE_WEIGHTS["suspicious_tld"]

    if whitelisted:
        score = SCORE_WEIGHTS["whitelist_override"]

    return {
        "content_score": round(min(max(score, 0.0), 1.0), 4),
        "snippet": snippet,
        "forms_count": forms_count,
        "buttons_count": buttons_count,
        "images_count": images_count,
        "ecommerce_keywords_count": ecommerce_count,
        "brand_domain": brand_domain,
        "exact_brand_match": exact_brand_match,
        "brand_subdomain": brand_subdomain,
        "informational": informational,
        "whitelisted": whitelisted,
        "suspicious_tld": suspicious_tld
    }


def process_url(url, keyword, use_selenium=False):
    """Procesa una URL y devuelve análisis."""
    html = get_html(url, use_selenium=use_selenium)
    if html is None:
        return None

    if html.startswith("ERROR:"):
        error_msg = html.replace("ERROR: ", "").lower()
        # Manejo de errores de conexión
        is_brand_or_retailer = is_brand_domain(url, keyword) or is_retailer_domain(url)
        if is_brand_or_retailer and any(err in error_msg for err in ERROR_MESSAGES.values()):
            return {
                "url": url,
                "keyword": keyword,
                "content_score": 0.0,
                "snippet": "Official distribution (unavailable)",
                "whitelisted": True,
                "official_unavailable": True
            }
        else:
            return None  # Suspicious o ignorar

    result = analyze_content(html, keyword, url)
    if result:
        result.update({"url": url, "keyword": keyword})
    return result


def run_brand_content_search(urls: list, keyword: str, max_workers=5, use_selenium=False):
    """Corre análisis paralelo de URLs."""
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(process_url, url, keyword, use_selenium) for url in urls]
        for future in as_completed(futures, timeout=30):  # Timeout global
            try:
                res = future.result()
                if res:
                    results.append(res)
            except TimeoutError:
                logger.warning("Timeout en future para process_url")
            except Exception as e:
                logger.error(f"Error en future: {e}")
    return results