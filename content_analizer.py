"""
Módulo robusto para análisis de contenido orientado a detección de phishing comercial.
- Entrada: brand (ej. "adidas") o lista de urls + brand objetivo
- Salida: lista de dicts con features, score, razones, categoría, y análisis de contenido.
- Requerimientos: requests, beautifulsoup4, joblib, tldextract, socket, ssl (estándar),
  python-Levenshtein o rapidfuzz (opcional), numpy (opcional), selenium (opcional).
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from urllib.parse import urlparse, urljoin
from joblib import Memory
from bs4 import BeautifulSoup
from datetime import datetime, timezone
import requests
import time
import random
import re
import math
import logging
import tldextract
import socket
import ssl
import hashlib
import os
import sqlite3
import backoff
import gzip
import json

# -------------------------
# Librerías opcionales
# -------------------------
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

try:
    from Levenshtein import jaro_winkler, distance as levenshtein_distance
except ImportError:
    try:
        from rapidfuzz.distance import Levenshtein as rf_lev
        from rapidfuzz.distance import JaroWinkler as rf_jw
        def levenshtein_distance(a, b):
            return rf_lev.distance(a, b)
        def jaro_winkler(a, b):
            return rf_jw.similarity(a, b) / 100.0
    except ImportError:
        def levenshtein_distance(a, b):
            if len(a) < len(b):
                a, b = b, a
            if not b:
                return len(a)
            previous_row = range(len(b) + 1)
            for i, c1 in enumerate(a):
                current_row = [i + 1]
                for j, c2 in enumerate(b):
                    insertions = previous_row[j + 1] + 1
                    deletions = current_row[j] + 1
                    substitutions = previous_row[j] + (c1 != c2)
                    current_row.append(min(insertions, deletions, substitutions))
                previous_row = current_row
            return float(previous_row[-1])
        def jaro_winkler(a, b):
            return 0.0

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# Suppress InsecureRequestWarning
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# -------------------------
# Configuraciones
# -------------------------
CACHE_DIR = "./content_cache"
memory = Memory(CACHE_DIR, verbose=0)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15"
]

SUSPICIOUS_TLDS = {
    "top", "tk", "xyz", "cf", "ga", "ml", "pw", "cc", "vip", "biz", "club", "online", "site",
    "work", "shop", "store", "website", "io", "link", "today", "bid", "date", "win", "win99"
}
TRUSTED_SSL_ISSUERS = {
    "Let's Encrypt", "DigiCert Inc", "Sectigo Limited", "Google Trust Services",
    "Amazon", "GlobalSign nv-sa", "GoDaddy.com, Inc."
}

CREDENTIAL_KEYWORDS = {
    "login", "signin", "sign-in", "sign_in", "verify", "verification", "validate",
    "password", "passwd", "pwd", "account", "unlock", "confirm", "confirm-account",
    "secure-login", "secure-access", "auth", "authentication", "user", "username",
    "email", "correo", "verify-account", "free-gift", "account-verification"
}
ECOMMERCE_KEYWORDS = {
    "cart", "checkout", "buy", "order", "payment", "invoice", "shipping", "track",
    "voucher", "coupon", "discount", "promo", "offer", "sale", "clearance",
    "carrito", "pagar", "comprar", "pedido", "envio", "factura", "rastreo",
    "descuento", "promocion", "oferta", "cupon"
}
URGENCY_KEYWORDS = {
    "urgent", "expires", "limited", "act now", "last chance", "hurry", "only today",
    "solo hoy", "ahora", "urgente", "expira", "limitado", "aprovecha", "ultimo",
    "oferta por tiempo", "final sale", "exclusive offer"
}
PHISHING_KEYWORDS = {
    "free gift", "win prize", "claim now", "verify account", "update payment",
    "secure your account", "login to claim", "exclusive deal", "limited stock",
    "regalo gratis", "gana premio", "reclamar ahora", "verificar cuenta",
    "actualizar pago", "asegura tu cuenta", "secure payment", "account suspended",
    "login required"
}

# CAMBIO: Nueva set de replica keywords
REPLICA_KEYWORDS = {
    "replica", "aaa quality", "super copy", "wholesale", "cheap {brand}", "100% original",
    "fake", "counterfeit", "reproduction", "reproduction", "knockoff", "repe", "dupe"
}

WEIGHTS = {
    "brand_in_domain": -0.7,
    "exact_brand_domain": -1.0,
    "brand_in_path": 0.03,
    "password_input": 0.35,
    "form_action_external": 0.4,
    "many_forms": 0.2,
    "credential_keywords": 0.4,
    "ecommerce_keywords": 0.02,
    "urgency_keywords": 0.2,
    "phishing_keywords": 0.45,
    "replica_keywords": 0.6,  # Nuevo: alto peso para replica keywords
    "suspicious_payment": 0.7,  # Nuevo: pago directo sin pasarela
    "contact_info_suspicious": 0.4,  # Nuevo: contacto insuficiente
    "multi_brand_detected": 0.5,  # Nuevo: inventario imposible,,,
    "images_logo_match": -0.4,
    "suspicious_tld": 0.25,
    "typo_similar_brand": 0.5,
    "external_links_ratio": 0.25,
    "low_text_to_form_ratio": 0.3,
    "informational_context": -0.5,
    "whitelisted_platform": -1.0,
    "https_missing": 0.3,
    "domain_young": 0.4,
    "ssl_invalid": 0.45,
    "ssl_young": 0.3,
    "ssl_untrusted_issuer": 0.35,
    "high_img_low_text": 0.3
}

SCORE_TO_FLAG = 0.8  # Aumentado
MIN_TEXT_LENGTH = 200
KEYWORD_PROXIMITY_WINDOW = 50
LEGIT_SUBDOMAINS = {"shop", "store", "www", "login", "account", "secure", "m", "en", "es"}
DB_PATH = "phishing_analysis.db"

# CAMBIO: Whitelist dinámico por marca
BRAND_WHITELISTS = {
    "cipriani": {
        "cipriani.com",  # Sitio principal de la marca Cipriani
        "ciprianidrinks.com",  # Tienda oficial de bebidas Cipriani
        "ciprianiresidencesmiami.com",  # Residencias Cipriani en Miami
        "mrchotels.com",  # Sitio oficial de Mr. C Hotels
        "mrccoconutgrove.com",  # Mr. C Coconut Grove en Miami
        "bellinirestaurant.com",  # Restaurante Bellini en Coconut Grove
        "ciprianienergygroup.com",  # Grupo Cipriani en energía renovable
    },
    "casa_cipriani": {
        "casacipriani.com",  # Sitio oficial de Casa Cipriani
        "casacipriani.com/miami",  # Casa Cipriani en Miami
        "casacipriani.com/milano",  # Casa Cipriani en Milán
    },
    "bellini": {
        "cipriani.com/bellini",  # Información sobre el cóctel Bellini
        "ciprianidrinks.com/en/bellini",  # Tienda oficial del cóctel Bellini
    },
    "mrc": {
        "mrchotels.com",  # Sitio oficial de Mr. C Hotels
        "mrccoconutgrove.com",  # Mr. C Coconut Grove en Miami
    },
    "berlini": {
        "bellinirestaurant.com",  # Restaurante Bellini en Coconut Grove
    },
}

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("PRAGMA table_info(analysis_results)")
        columns = [col[1] for col in c.fetchall()]
        if "content_analysis" not in columns:
            try:
                c.execute("ALTER TABLE analysis_results RENAME TO analysis_results_old")
                logger.info("Tabla antigua renombrada a analysis_results_old")
            except sqlite3.OperationalError:
                logger.info("No se encontró tabla antigua, creando nueva")
        c.execute("""
            CREATE TABLE IF NOT EXISTS analysis_results (
                url TEXT,
                base_domain TEXT,
                score REAL,
                category TEXT,
                reasons TEXT,
                analyzed_at TEXT,
                analysis_time_s REAL,
                content_analysis TEXT,
                PRIMARY KEY (url, analyzed_at)
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_base_domain ON analysis_results (base_domain)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_score ON analysis_results (score)")
        if "content_analysis" not in columns:
            try:
                c.execute("""
                    INSERT INTO analysis_results (url, base_domain, score, category, reasons, analyzed_at, analysis_time_s)
                    SELECT url, base_domain, score, category, reasons, analyzed_at, analysis_time_s
                    FROM analysis_results_old
                """)
                c.execute("DROP TABLE analysis_results_old")
                logger.info("Datos migrados desde analysis_results_old")
            except sqlite3.OperationalError:
                pass
        conn.commit()

# -------------------------
# Typosquatting
# -------------------------
def compute_typosquat_score(brand: str, domain: str) -> float:
    if not brand or not domain:
        return 0.0
    brand = brand.lower()
    domain_core = tldextract.extract(domain).domain.lower()
    if domain_core == brand:
        return 0.0
    max_len = max(len(brand), len(domain_core))
    if max_len == 0:
        return 0.0
    lev = levenshtein_distance(brand, domain_core) / max_len
    jw = jaro_winkler(brand, domain_core)
    # CAMBIO: Combinación ponderada
    return 0.6 * (1 - lev) + 0.4 * jw

# CAMBIO: Whitelist dinámico
def is_whitelisted(domain: str, brand: str) -> bool:
    return domain.lower() in BRAND_WHITELISTS.get(brand.lower(), set())

# -------------------------
# Selenium driver management
# -------------------------
def get_selenium_driver(headless=True, timeout=20):
    if not SELENIUM_AVAILABLE:
        raise RuntimeError("Selenium no disponible.")
    options = Options()
    if headless:
        options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-gpu")
    options.add_argument("--disable-dev-shm-usage")
    prefs = {"profile.managed_default_content_settings.images": 2}
    options.add_experimental_option("prefs", prefs)
    driver = webdriver.Chrome(options=options)
    driver.set_page_load_timeout(timeout)
    return driver

# -------------------------
# UTIL: WHOIS, SSL, image hash
# -------------------------
@backoff.on_exception(backoff.expo, Exception, max_tries=3)
def manual_whois(domain):
    try:
        tld = tldextract.extract(domain).suffix
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(("whois.iana.org", 43))
        sock.sendall(f"{tld}\r\n".encode())
        response = b""
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data
        sock.close()
        resp = response.decode(errors="ignore")
        whois_server = re.search(r"whois:\s+(.+)", resp)
        if not whois_server:
            return {"error": "No WHOIS server found", "age_days": None, "whois_suspicious": False}

        whois_server = whois_server.group(1).strip()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((whois_server, 43))
        sock.sendall(f"{domain}\r\n".encode())
        response = b""
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data
        sock.close()
        resp = response.decode(errors="ignore")
        creation = re.search(r"(Creation Date|Created On|Registered on):\s*(\d{4}-\d{2}-\d{2})", resp, re.I)
        creation_date = creation.group(2).strip() if creation else None
        if creation_date:
            try:
                creation_dt = datetime.strptime(creation_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                age_days = (datetime.now(timezone.utc) - creation_dt).days
            except Exception:
                age_days = None
        else:
            age_days = None
        # CAMBIO: Penalización si registrante es privado o país sospechoso
        whois_suspicious = "private" in resp.lower() or "redacted" in resp.lower() or any(p in resp.lower() for p in ["china", "russia"])
        return {"age_days": age_days, "raw": resp[:500], "whois_suspicious": whois_suspicious}
    except Exception as e:
        return {"error": str(e), "age_days": None, "whois_suspicious": False}

def check_ssl(url):
    hostname = urlparse(url).hostname
    if not hostname:
        return {"valid": False, "error": "No hostname", "age_days": None, "issuer": "Unknown"}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                issuer_tuple = dict(x[0] for x in cert.get("issuer", []))
                issuer = issuer_tuple.get("organizationName", "Unknown")
                not_before_str = cert.get("notBefore")
                not_after_str = cert.get("notAfter")
                if not_before_str and not_after_str:
                    try:
                        not_before = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        valid = datetime.now(timezone.utc) > not_before and datetime.now(timezone.utc) < not_after
                        age_days = (datetime.now(timezone.utc) - not_before).days
                    except Exception:
                        valid = True if urlparse(url).scheme == "https" else False
                        age_days = None
                else:
                    valid = True if urlparse(url).scheme == "https" else False
                    age_days = None
                return {"valid": valid, "issuer": issuer, "age_days": age_days}
    except ssl.SSLError as e:
        return {"valid": True if urlparse(url).scheme == "https" else False, "error": f"SSL error: {e}", "age_days": None, "issuer": "Unknown"}
    except Exception as e:
        return {"valid": True if urlparse(url).scheme == "https" else False, "error": str(e), "age_days": None, "issuer": "Unknown"}

@lru_cache(maxsize=1)
def image_perceptual_hash(image_data):
    if not image_data:
        return None
    try:
        return hashlib.md5(image_data).hexdigest()
    except Exception:
        return None

def compare_images(hash1, hash2):
    if hash1 is None or hash2 is None:
        return 1.0
    return sum(c1 != c2 for c1, c2 in zip(hash1, hash2)) / len(hash1)

# -------------------------
# Network fetch (cacheado)
# -------------------------
@memory.cache
def _cached_requests_get(url, headers_tuple, timeout):
    headers = dict(headers_tuple)
    try:
        r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True, verify=False)
        compressed = gzip.compress(r.text.encode('utf-8')) if r.status_code == 200 else b""
        return (r.status_code, r.url, compressed)
    except Exception as e:
        return (None, url, str(e))

def fetch_html(url, use_selenium=False, timeout=10):
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    headers_tuple = tuple(sorted(headers.items()))
    try:
        status, final_url, compressed = _cached_requests_get(url, headers_tuple, timeout)
        text = gzip.decompress(compressed).decode('utf-8') if status == 200 else ""
        if status == 200 and text and len(text.strip()) > 0 and not use_selenium:
            return {"ok": True, "status": status, "final_url": final_url, "html": text}
        if use_selenium and SELENIUM_AVAILABLE:
            try:
                with get_selenium_driver() as driver:
                    driver.get(url)
                    time.sleep(random.uniform(1, 3))
                    page = driver.page_source
                    return {"ok": True, "status": 200, "final_url": driver.current_url, "html": page}
            except Exception as e:
                return {"ok": False, "status": status, "final_url": final_url, "error": f"selenium error: {e}"}
        return {"ok": False, "status": status, "final_url": final_url, "error": f"HTTP {status}"}
    except Exception as e:
        return {"ok": False, "status": None, "final_url": url, "error": str(e)}

# -------------------------
# Feature extraction
# -------------------------
def extract_domain_info(url):
    parsed = urlparse(url)
    host = parsed.hostname or parsed.netloc or ""
    ext = tldextract.extract(host)
    base = (ext.domain + "." + ext.suffix) if ext.suffix else host
    return {"host": host.lower(), "base_domain": base.lower() if base else "", "subdomain": ext.subdomain.lower(), "tld": ext.suffix.lower()}

def normalize_text(s):
    return re.sub(r'\s+', ' ', s).strip().lower() if s else ""

def find_brand_in_text(brand, text):
    brand_low = brand.lower()
    count = len(re.findall(rf"\b{re.escape(brand_low)}\b", text))
    fuzzy_matches = []
    text_lower = text.lower()
    words = re.findall(r'\b\w+\b', text_lower)
    for word in words:
        if jaro_winkler(brand_low, word) > 0.9:
            count += 1
            fuzzy_matches.append(word)
    return count > 0, count, fuzzy_matches

def extract_text_snippets(text, keywords, brand, window=50):
    snippets = []
    text_lower = text.lower()
    for kw in keywords:
        for m in re.finditer(rf"\b{re.escape(kw)}\b", text_lower):
            start = max(0, m.start() - window)
            end = m.end() + window
            snippet = text[start:end].strip()
            snippets.append(snippet[:100])
    return snippets[:5]

def detect_logo_images(soup, brand, known_logo_url=None, page_base_url=None):
    found = []
    similarity_scores = []
    brand_low = brand.lower()
    count = 0
    for img in soup.find_all("img"):
        if count >= 5:
            break
        try:
            src = img.get("src")
            attrs = " ".join(filter(None, (img.get("alt"), img.get("title"), src))).lower()
            if brand_low in attrs or "logo" in attrs:
                found.append({"src": src, "alt": img.get("alt"), "title": img.get("title")})
                count += 1
            if known_logo_url and src and NUMPY_AVAILABLE:
                img_src = urljoin(page_base_url, src) if page_base_url else src
                try:
                    resp = requests.get(img_src, timeout=3)
                    if resp.status_code == 200:
                        known = requests.get(known_logo_url, timeout=3).content
                        h_known = image_perceptual_hash(known)
                        h_img = image_perceptual_hash(resp.content)
                        sim = 1 - compare_images(h_known, h_img)
                        similarity_scores.append(sim)
                except Exception:
                    continue
        except Exception:
            continue
    return found, max(similarity_scores) if similarity_scores else 0.0

def analyze_forms(soup, base_domain):
    forms = soup.find_all("form")
    forms_info = []
    suspicious_inputs = {"card_number", "credit_card", "cvv", "card_expiry", "billing"}
    for f in forms:
        try:
            action = f.get("action") or ""
            method = (f.get("method") or "get").lower()
            inputs = f.find_all("input")
            input_details = []
            suspicious = False
            for i in inputs:
                input_type = (i.get("type") or "text").lower()
                input_name = (i.get("name") or i.get("id") or "").lower()
                input_details.append({"type": input_type, "name": input_name})
                if any(s in input_name for s in suspicious_inputs):
                    suspicious = True
            has_password = any(i["type"] == "password" for i in input_details)
            has_email = any(i["type"] == "email" or "email" in i["name"] for i in input_details)
            action_domain = ""
            if action:
                resolved = urljoin(f"https://{base_domain}", action)
                parsed = urlparse(resolved)
                action_domain = parsed.hostname or ""
            forms_info.append({
                "action": action,
                "action_domain": action_domain.lower(),
                "method": method,
                "has_password": has_password,
                "has_email": has_email,
                "suspicious_inputs": suspicious,
                "inputs": input_details,
                "inputs_count": len(inputs)
            })
        except Exception:
            continue
    external_actions = [1 for fi in forms_info if fi["action_domain"] and fi["action_domain"] != base_domain]
    external_ratio = (sum(external_actions) / max(1, len(forms_info))) if forms_info else 0.0
    return {
        "forms_count": len(forms_info),
        "forms": forms_info,
        "forms_external_action_ratio": external_ratio,
        "suspicious_forms_count": sum(1 for fi in forms_info if fi["suspicious_inputs"]),
        "suspicious_payment": any(fi["suspicious_inputs"] for fi in forms_info) and not features.get("whitelisted_platform", False)  # CAMBIO: Nueva feature suspicious_payment
    }

def external_links_ratio(soup, page_domain):
    links = [a.get("href") for a in soup.find_all("a", href=True)]
    total = 0
    external = 0
    for href in links:
        try:
            total += 1
            parsed = urlparse(urljoin(page_domain, href))
            h = parsed.hostname or ""
            if h and not (h.endswith(page_domain) or page_domain in h):
                external += 1
        except Exception:
            continue
    return (external / total) if total else 0.0

def count_keywords_with_context(text, keywords, brand, window=KEYWORD_PROXIMITY_WINDOW):
    hits = set()
    cnt = 0
    text_lower = text.lower()
    for kw in keywords:
        for m in re.finditer(rf"\b{re.escape(kw)}\b", text_lower):
            hits.add(kw)
            cnt += 1
    return hits, cnt

def count_credential_keywords(text, brand):
    return count_keywords_with_context(text, CREDENTIAL_KEYWORDS, brand)

def count_ecommerce_keywords(text, brand):
    return count_keywords_with_context(text, ECOMMERCE_KEYWORDS, brand)

def count_urgency_keywords(text, brand):
    return count_keywords_with_context(text, URGENCY_KEYWORDS, brand)

def count_phishing_keywords(text, brand):
    return count_keywords_with_context(text, PHISHING_KEYWORDS, brand)

def count_replica_keywords(text, brand):
    return count_keywords_with_context(text, REPLICA_KEYWORDS, brand)

# -------------------------
# Scoring
# -------------------------
def score_page(features, brand):
    reasons = []
    score = 0.0

    if features.get("exact_brand_domain"):
        score += WEIGHTS["exact_brand_domain"]
        reasons.append("Dominio exacto de la marca (confianza)")
    elif features.get("brand_in_domain"):
        score += WEIGHTS["brand_in_domain"]
        reasons.append("Marca en dominio (reduce sospecha)")
    else:
        if features.get("brand_in_path"):
            score += WEIGHTS["brand_in_path"]
            reasons.append("Marca en path/subdominio pero no en dominio base (posible spoof)")

    # CAMBIO: Whitelist dinámico
    if is_whitelisted(features.get("base_domain", ""), brand):
        score += WEIGHTS["whitelisted_platform"]
        reasons.append("Plataforma oficial / retailer (whitelist override)")

    if features.get("password_inputs_count", 0) > 0:
        n = features.get("password_inputs_count", 0)
        score += WEIGHTS["password_input"] * min(1.0, n)
        reasons.append(f"Formularios con campo password: {n}")
    if features.get("email_inputs_count", 0) > 0:
        n = features.get("email_inputs_count", 0)
        score += WEIGHTS["password_input"] * min(1.0, n)
        reasons.append(f"Formularios con campo email: {n}")
    if features.get("suspicious_forms_count", 0) > 0:
        n = features.get("suspicious_forms_count", 0)
        score += WEIGHTS["password_input"] * min(1.0, n)
        reasons.append(f"Formularios con campos sospechosos (e.g., card_number): {n}")
    if features.get("forms_count", 0) > 2:
        score += WEIGHTS["many_forms"]
        reasons.append(f"Multiples formularios ({features.get('forms_count')})")

    if features.get("forms_external_action_ratio", 0) > 0.2:
        score += WEIGHTS["form_action_external"] * features.get("forms_external_action_ratio")
        reasons.append(f"Ratio forms->dominios externos: {round(features.get('forms_external_action_ratio'),2)}")

    cred_count = features.get("credential_keywords_count", 0)
    if cred_count > 0:
        score += WEIGHTS["credential_keywords"] * min(1.0, math.log(1 + cred_count) / math.log(6))
        reasons.append(f"Keywords de credenciales en página: {cred_count}")

    eco_count = features.get("ecommerce_keywords_count", 0)
    # CAMBIO: Solo sumar ecommerce_keywords si hay señales fuertes
    if eco_count > 0 and (
        features.get("password_inputs_count", 0) > 0 or
        features.get("suspicious_forms_count", 0) > 0 or
        features.get("phishing_keywords_count", 0) > 0
    ):
        score += WEIGHTS["ecommerce_keywords"] * min(1.0, eco_count/10)
        reasons.append(f"Keywords ecommerce junto a formularios o phishing: {eco_count}")

    urg_count = features.get("urgency_keywords_count", 0)
    # CAMBIO: Solo sumar urgency_keywords si hay phishing_keywords o formularios sospechosos
    if urg_count > 0 and (
        features.get("phishing_keywords_count", 0) > 0 or
        features.get("password_inputs_count", 0) > 0 or
        features.get("suspicious_forms_count", 0) > 0
    ):
        score += WEIGHTS["urgency_keywords"] * min(1.0, urg_count/5)
        reasons.append(f"Keywords de urgencia con señales fuertes: {urg_count}")

    phish_count = features.get("phishing_keywords_count", 0)
    # CAMBIO: Solo sumar phishing_keywords si hay ≥2 o están cerca de la marca
    if phish_count >= 2 or (
        phish_count > 0 and any(brand.lower() in snippet.lower() for snippet in features.get("content_analysis", {}).get("text_snippets", []))
    ):
        score += WEIGHTS["phishing_keywords"] * min(1.0, phish_count/5)
        reasons.append(f"Keywords de phishing (múltiples o cerca de marca): {phish_count}")

    replica_count = features.get("replica_keywords_count", 0)
    if replica_count > 0:
        score += WEIGHTS["replica_keywords"]
        reasons.append(f"Keywords de replica/mercancía falsa: {replica_count}")

    if features.get("suspicious_payment", False):
        score += WEIGHTS["suspicious_payment"]
        reasons.append("Método de pago sospechoso (tarjeta directa sin pasarela confiable)")

    if features.get("contact_info_suspicious", True):
        score += WEIGHTS["contact_info_suspicious"]
        reasons.append("Información de contacto insuficiente o email gratuito")

    if features.get("multi_brand_detected", False):
        score += WEIGHTS["multi_brand_detected"]
        reasons.append("Inventario con múltiples marcas no relacionadas (scam típico)")

    if features.get("logo_similarity", 0) > 0.8:
        score += WEIGHTS["images_logo_match"]
        reasons.append(f"Logo similar detectado (sim: {round(features.get('logo_similarity'),2)})")

    if features.get("tld") in SUSPICIOUS_TLDS:
        score += WEIGHTS["suspicious_tld"]
        reasons.append(f"TLD sospechoso: .{features.get('tld')}")

    if features.get("typo_score", 0) > 0.5:
        score += WEIGHTS["typo_similar_brand"] * min(1.0, features.get("typo_score"))
        reasons.append(f"Similitud tipográfica con marca: {round(features.get('typo_score'),2)}")

    if features.get("external_links_ratio", 0) > 0.6:
        score += WEIGHTS["external_links_ratio"]
        reasons.append("Alta proporción de enlaces externos (posible redirección/affiliate)")

    if features.get("text_len", 0) < MIN_TEXT_LENGTH and features.get("forms_count", 0) > 0:
        score += WEIGHTS["low_text_to_form_ratio"]
        reasons.append("Poca cantidad de texto frente a formularios (página muy simple)")

    if features.get("informational_context"):
        score += WEIGHTS["informational_context"]
        reasons.append("Contenido claramente educativo/informativo (reduce sospecha)")

    if features.get("whitelisted_platform"):
        score += WEIGHTS["whitelisted_platform"]
        reasons.append("Plataforma oficial / retailer (whitelist override)")

    if not features.get("is_https"):
        score += WEIGHTS["https_missing"]
        reasons.append("Sin HTTPS")

    if features.get("domain_age_days") is not None and features.get("domain_age_days") < 180:
        score += WEIGHTS["domain_young"]
        reasons.append(f"Domini o joven: {features.get('domain_age_days')} días")

    if features.get("ssl_valid") is not None and not features.get("ssl_valid"):
        score += WEIGHTS["ssl_invalid"]
        reasons.append("SSL inválido o ausente")

    # CAMBIO: Penalizar SSL joven solo si el dominio también es joven (<90 días)
    ssl_age = features.get("ssl_age_days")
    domain_age = features.get("domain_age_days")
    if ssl_age is not None and domain_age is not None and ssl_age < 30 and domain_age < 90:
        score += WEIGHTS["ssl_young"]
        reasons.append(f"Cert SSL joven: {ssl_age} días")

    if features.get("ssl_issuer") and features.get("ssl_issuer") not in TRUSTED_SSL_ISSUERS:
        score += WEIGHTS["ssl_untrusted_issuer"]
        reasons.append(f"Emisor SSL no confiable: {features.get('ssl_issuer')}")

    img_count = features.get("images_count", 0)
    if img_count > 20 and features.get("text_len", 0) < 1000:
        score += WEIGHTS["high_img_low_text"]
        reasons.append("Alta cantidad de imágenes con poco texto (posible fake shop)")

    s = float(score)
    sigmoid = 1 / (1 + math.exp(-3.0 * s))
    final_score = max(0.0, min(1.0, sigmoid))

    if features.get("exact_brand_domain") or features.get("whitelisted_platform") or (
        features.get("logo_similarity", 0) > 0.8 and features.get("domain_age_days", 0) > 365 and features.get("ssl_valid")
    ):
        final_score = max(0.0, final_score - 0.5)
        reasons.append("Override: Señales legit fuertes (dominio viejo, SSL válido, logo match)")

    reasons = list(set(reasons))
    return final_score, reasons

# -------------------------
# Pipeline single URL
# -------------------------
def analyze_url(url, brand, use_selenium=False, timeout=10, known_logo_url=None):
    start = time.time()
    init_db()
    res_fetch = fetch_html(url, use_selenium=use_selenium, timeout=timeout)
    domain_info = extract_domain_info(url)

    features = {
        "url": url,
        "final_url": res_fetch.get("final_url", url),
        "base_domain": domain_info.get("base_domain"),
        "host": domain_info.get("host"),
        "tld": domain_info.get("tld"),
        "subdomain": domain_info.get("subdomain"),
        "is_https": urlparse(url).scheme.lower() == "https",
        "fetched_ok": res_fetch.get("ok", False),
        "http_status": res_fetch.get("status")
    }

    content_analysis = {
        "text_snippets": [],
        "forms_details": [],
        "logo_matches": []
    }

    if not res_fetch.get("ok"):
        features.update({
            "error": res_fetch.get("error"),
            "score": 0.0,
            "reasons": ["No se pudo recuperar HTML" + (f": {res_fetch.get('error')}" if res_fetch.get('error') else "")],
            "content_analysis": content_analysis
        })
        return features

    html = res_fetch.get("html") or ""
    soup = BeautifulSoup(html, "html.parser")
    text = normalize_text(soup.get_text(separator=" ", strip=True))

    # Extraer fragmentos de texto
    all_keywords = CREDENTIAL_KEYWORDS | ECOMMERCE_KEYWORDS | URGENCY_KEYWORDS | PHISHING_KEYWORDS
    content_analysis["text_snippets"] = extract_text_snippets(text, all_keywords, brand)

    features.update({
        "text_len": len(text),
        "title": normalize_text(soup.title.string) if soup.title and soup.title.string else "",
        "images_count": len(soup.find_all("img")),
        "buttons_count": len(soup.find_all("button")),
    })

    brand_in_domain = (brand.lower() in (domain_info.get("base_domain") or "")) or (brand.lower() in (domain_info.get("host") or ""))
    ext = tldextract.extract(domain_info.get("base_domain") or "")
    exact_brand_domain = ext.domain.lower() == brand.lower() or (ext.subdomain.lower() in LEGIT_SUBDOMAINS and ext.domain.lower() == brand.lower())
    path = urlparse(url).path.lower()
    brand_in_path = (brand.lower() in path) or (brand.lower() in (domain_info.get("subdomain") or ""))

    features["brand_in_domain"] = brand_in_domain
    features["exact_brand_domain"] = exact_brand_domain
    features["brand_in_path"] = brand_in_path

    logo_matches, logo_sim = detect_logo_images(soup, brand, known_logo_url, page_base_url=features.get("final_url"))
    features["logo_matches"] = logo_matches
    features["logo_similarity"] = logo_sim
    content_analysis["logo_matches"] = logo_matches

    forms_info = analyze_forms(soup, domain_info.get("base_domain") or "")
    features.update(forms_info)
    password_inputs = sum(1 for f in forms_info.get("forms", []) if f.get("has_password"))
    email_inputs = sum(1 for f in forms_info.get("forms", []) if f.get("has_email"))
    features["password_inputs_count"] = password_inputs
    features["email_inputs_count"] = email_inputs
    content_analysis["forms_details"] = forms_info.get("forms", [])

    features["external_links_ratio"] = external_links_ratio(soup, domain_info.get("base_domain") or "")

    cred_hits, cred_count = count_credential_keywords(text, brand)
    features["credential_keywords_hits"] = list(cred_hits)
    features["credential_keywords_count"] = cred_count

    eco_hits, eco_count = count_ecommerce_keywords(text, brand)
    features["ecommerce_keywords_hits"] = list(eco_hits)
    features["ecommerce_keywords_count"] = eco_count

    urg_hits, urg_count = count_urgency_keywords(text, brand)
    features["urgency_keywords_hits"] = list(urg_hits)
    features["urgency_keywords_count"] = urg_count

    phish_hits, phish_count = count_phishing_keywords(text, brand)
    features["phishing_keywords_hits"] = list(phish_hits)
    features["phishing_keywords_count"] = phish_count

    replica_hits, replica_count = count_replica_keywords(text, brand)
    features["replica_keywords_hits"] = list(replica_hits)
    features["replica_keywords_count"] = replica_count

    metas = {(m.get("name") or "").lower(): m.get("content", "") for m in soup.find_all("meta", attrs={"name": True, "content": True})}
    features["meta"] = metas

    info_context = False
    info_patterns = ["how to", "how-to", "guide", "tutorial", "avoid", "identify", "scam", "scam alert", "warning", "protect yourself", "blog", "news"]
    for p in info_patterns:
        if p in (text[:300] or "") or p in features["title"] or any(p in v.lower() for v in metas.values()):
            info_context = True
            break
    features["informational_context"] = info_context

    netloc = urlparse(url).netloc.lower()
    features["whitelisted_platform"] = any(x in netloc for x in (
        "play.google.com", "apps.apple.com", "amazon.com", "microsoft.com", "nordstrom.com",
        "nordstromrack.com", "zappos.com", "coupons.com", "usatoday.com", "footlocker.com",
        "falabella.com.pe", "cnn.com", "yahoo.com", "businessinsider.com", "runnersworld.com",
        "wired.com", "travelandleisure.com", "tomsguide.com", "slickdeals.net",
        "promodescuentos.com", "foxdeportes.com", "sportico.com.mx", "deporte-outlet.es",
        "marti.mx", "dportenis.mx", "diadora.com", "championmexico.com.mx"
    ))

    typo_score = compute_typosquat_score(brand, domain_info.get("base_domain") or "")
    features["typo_score"] = typo_score

    whois_res = manual_whois(domain_info.get("base_domain") or "")
    features["domain_age_days"] = whois_res.get("age_days", None)
    features["whois_suspicious"] = whois_res.get("whois_suspicious", False)

    if features.get("is_https"):
        ssl_res = check_ssl(url)
        features["ssl_valid"] = ssl_res.get("valid", True)
        features["ssl_issuer"] = ssl_res.get("issuer", "Unknown")
        features["ssl_age_days"] = ssl_res.get("age_days", None)
    else:
        features["ssl_valid"] = False
        features["ssl_issuer"] = None
        features["ssl_age_days"] = None

    page_score, reasons = score_page(features, brand)
    features["score"] = round(page_score, 4)
    features["reasons"] = reasons
    features["analyzed_at"] = datetime.now(timezone.utc).isoformat()
    features["analysis_time_s"] = round(time.time() - start, 3)
    features["content_analysis"] = content_analysis

    # CAMBIO: Nueva categorización
    if features["score"] >= 0.7:
        category = "phishing"
    elif features["score"] >= 0.3:
        category = "suspect"
    else:
        category = "legit"
    features["category"] = category

    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("""
            INSERT OR REPLACE INTO analysis_results (url, base_domain, score, category, reasons, analyzed_at, analysis_time_s, content_analysis)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            features["url"],
            features["base_domain"],
            features["score"],
            features["category"],
            json.dumps(features["reasons"]),
            features["analyzed_at"],
            features["analysis_time_s"],
            json.dumps(features["content_analysis"])
        ))
        conn.commit()

    return features

# -------------------------
# Batch runner
# -------------------------
def run_content_analysis(urls, brand, max_workers=8, use_selenium=False, timeout=15, known_logo_url=None, min_score_filter=0.3):
    results = []
    if not urls:
        return results
    batch_size = 100
    for i in range(0, len(urls), batch_size):
        batch_urls = urls[i:i + batch_size]
        logger.info("Procesando lote de %d URLs (%d/%d)", len(batch_urls), i + len(batch_urls), len(urls))
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(analyze_url, u, brand, use_selenium, timeout, known_logo_url): u for u in batch_urls}
            for fut in as_completed(futures):
                try:
                    r = fut.result(timeout=timeout * 2)
                    if r and r.get("score", 0) >= min_score_filter:
                        results.append(r)
                except Exception as e:
                    logger.warning(f"Error procesando {futures[fut]}: {e}")
                    results.append({
                        "url": futures[fut],
                        "score": 0.0,
                        "reasons": [f"Error en análisis: {str(e)}"],
                        "category": "error",
                        "analyzed_at": datetime.now(timezone.utc).isoformat(),
                        "content_analysis": {}
                    })
    results.sort(key=lambda x: x.get("score", 0), reverse=True)
    return results

# -------------------------
# SEARCH CANDIDATES
# -------------------------
SEARCH_QUERIES_TEMPLATES = [
    "{brand} comprar",
    "{brand} oferta",
    "{brand} tienda",
    "{brand} descuento",
    "{brand} promo",
    "{brand} outlet",
    "{brand} sale",
    "{brand} login",
    "{brand} shop",
    "{brand} deals",
    "{brand} clearance",
    "{brand} rebajas",
    "{brand} promociones",
    "{brand} black friday",
    "{brand} cyber monday",
    "restaurante {brand}",
    "hotel {brand}",
    "residencias {brand}",
    "cóctel {brand}",
    "bebidas {brand}",
    "eventos {brand}",
    "club privado {brand}",
    "compra online {brand}",
    "reservas {brand}",
    "ofertas hotel {brand}",
    "promociones restaurante {brand}"
    "{brand} buy",
    "{brand} offer",
    "{brand} shop",
    "{brand} discount",
    "{brand} promo",
    "{brand} outlet",
    "{brand} sale",
    "{brand} login",
    "{brand} drinks",
    "{brand} restaurant",
    "{brand} hotel",
    "{brand} reservations",
    "{brand} deals",
    "{brand} promotions",
    "{brand} online booking",
]

NEWS_SOCIAL_PATTERNS = [
    "wikipedia.org", "facebook.com", "instagram.com", "x.com", "linkedin.com", "youtube.com",
    "tiktok.com", "reddit.com", "bing.com", "google.com", "apple.com"
]

@backoff.on_exception(backoff.expo, Exception, max_tries=5)
@lru_cache(maxsize=128)
def ddg_search_html(query, max_results=50, timeout=10):
    try:
        q = requests.utils.requote_uri(query)
        url = f"https://html.duckduckgo.com/html/?q={q}"
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        r = requests.get(url, headers=headers, timeout=timeout)
        if r.status_code != 200:
            logger.warning("DDG HTTP %d: %s", r.status_code, r.text[:100])
            return []
        soup = BeautifulSoup(r.text, "html.parser")
        anchors = soup.find_all("a", attrs={"class": "result__a"}, href=True)
        urls = []
        for a in anchors:
            href = a["href"]
            if "uddg=" in href:
                m = re.search(r"uddg=(http[^&]+)", href)
                if m:
                    target = requests.utils.unquote(m.group(1))
                else:
                    target = href
            else:
                target = href
            urls.append(target)
            if len(urls) >= max_results:
                break
        return urls
    except Exception as e:
        logger.debug("DDG search error: %s", e)
        return []

def filter_candidate_urls(urls, brand, allow_news=False):
    seen = set()
    filtered = []
    brand_low = brand.lower()
    for u in urls:
        try:
            u = u.strip()
            if not u or u in seen:
                continue
            parsed = urlparse(u)
            host = (parsed.hostname or "").lower()
            if not host:
                continue
            if not allow_news and any(pat in host for pat in NEWS_SOCIAL_PATTERNS):
                continue
            if host.endswith("duckduckgo.com") or host.endswith("bing.com"):
                continue
            seen.add(u)
            filtered.append(u)
        except Exception:
            continue
    return filtered

def search_candidates(brand, max_results=1000, per_query=100, allow_news=False):
    urls = []
    for t in SEARCH_QUERIES_TEMPLATES:
        q = t.format(brand=brand)
        try:
            found = ddg_search_html(q, max_results=per_query)
            urls.extend(found)
            if len(urls) >= max_results:
                break
            time.sleep(random.uniform(5.0, 7.0))
        except Exception as e:
            logger.debug("Error en ddg_search_html: %s", e)
    urls = filter_candidate_urls(urls, brand, allow_news=allow_news)
    return urls[:max_results]

# -------------------------
# High-level wrapper
# -------------------------
def find_and_analyze(brand, max_results=1000, max_workers=8, use_selenium=False, timeout=15, known_logo_url=None, min_score_filter=0.3, allow_news=False):
    logger.info("🔍 Buscando candidatos para la marca: %s", brand)
    candidates = search_candidates(brand, max_results=max_results, per_query=max(100, max_results//5), allow_news=allow_news)
    logger.info("✅ Encontrados %d candidatos (filtrados).", len(candidates))
    if not candidates:
        return []
    logger.info("📊 Analizando contenido de %d URLs...", len(candidates))
    results = run_content_analysis(candidates, brand, max_workers=max_workers, use_selenium=use_selenium, timeout=timeout, known_logo_url=known_logo_url, min_score_filter=min_score_filter)
    logger.info("📌 Análisis finalizado. Resultados: %d", len(results))
    return results

# -------------------------
# Run
# -------------------------
if __name__ == "__main__":
    import json

    # Configuración fija
    brand = "Cipriani, berlini, mr c, socialista"
    max_results = 500
    max_workers = 4  # Aumentado para procesar más URLs
    use_selenium = False
    timeout = 20
    min_score_filter = 0.3  # Reducido para incluir más resultados
    output_file = "results.json"
    allow_news = True
    known_logo_url = "https://upload.wikimedia.org/wikipedia/commons/2/20/Adidas_Logo.svg"  # Logosa Carfar

    # Ejecutar análisis
    results = find_and_analyze(
        brand=brand,
        max_results=max_results,
        max_workers=max_workers,
        use_selenium=use_selenium,
        timeout=timeout,
        known_logo_url=known_logo_url,
        min_score_filter=min_score_filter,
        allow_news=allow_news
    )

    # Guardar resultados en JSON
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    # Imprimir resumen en consola
    print(f"\n✅ Análisis completado. Resultados exportados a {output_file}")
    for r in results[:30]:
        print("============================================================")
        print("URL:", r.get("url"))
        print("Final URL:", r.get("final_url"))
        print("Score:", r.get("score"))
        print("Category:", r.get("category"))
        print("Razones:", r.get("reasons"))
        print("Dominio:", r.get("base_domain"), "| SSL:", r.get("ssl_valid"), "| Edad dominio:", r.get("domain_age_days"))
        print("Análisis de Contenido:")
        print("  - Fragmentos de Texto:", r.get("content_analysis", {}).get("text_snippets", []))
        print("  - Formularios:", r.get("content_analysis", {}).get("forms_details", []))
        print("  - Logos Detectados:", r.get("content_analysis", {}).get("logo_matches", []))
    print("============================================================")