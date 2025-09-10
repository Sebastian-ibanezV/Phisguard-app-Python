# whois_lookup.py
"""
whois_lookup.py - WHOIS + DNS + heuristics para detección de phishing
Diseñado para:
 - Detectar phishing de robo de credenciales y phishing comercial (tiendas falsas)
 - Guiarse por UNA LISTA DE MARCAS (brands) pasada por input para reducir falsos positivos
 - Guardar resultados en caché SQLite (database.save_domain_info / get_cached_domain_info)
 - Evitar marcar como sospechoso páginas educativas / reportes que contengan palabras como "scam", "fake", etc.

IMPORTANTE:
 - Llama is_suspicious(domain_info, brands=brands_list) desde tu pipeline principal.
 - Si no pasas brands, el detector es más conservador y NO marcará sitios solo por "login".
"""

import time
import re
from datetime import datetime
from urllib.parse import urlparse

import whois
import dns.resolver
import tldextract
from Levenshtein import jaro_winkler, distance

from database import get_cached_domain_info, save_domain_info

import logging
logger = logging.getLogger(__name__)

# -------------------------
# Config / thresholds
# -------------------------
SUSPICIOUS_THRESHOLD = 50

# Weights (ajusta según experiencia)
CREATION_LESS_THAN_DAYS = 180
CREATION_WEIGHT = 20
NO_EMAIL_WEIGHT = 8
NO_REGISTRAR_WEIGHT = 12
HIGH_RISK_TLD_WEIGHT = 45
LOW_RISK_TLD_WEIGHT = 12
NO_MX_WEIGHT = 12
TTL_SHORT_WEIGHT = 10   # TTL < TTL_SHORT_SEC
TTL_SHORT_SEC = 300
NO_IP_WEIGHT = 10
NS_FEW_WEIGHT = 10
UNTRUSTED_NS_WEIGHT = 10
MULTIPLE_IPS_WEIGHT = 10
HTTPS_MISSING_WEIGHT = 12
SIMILAR_DOMAIN_WEIGHT = 40

# Keyword weights
HIGH_CONF_BASE = 18      # peso base para keywords tipo login/verify
HIGH_CONF_BRAND_BOOST = 12  # adicional si la keyword aparece en contexto con la marca
LOW_PROMO_WEIGHT = 3
URGENCY_WEIGHT = 4

# Simpler thresholds
MIN_BRAND_TOKEN_MATCHES = 1  # cuántas coincidencias de token de marca consideramos "mencionada"

INFLIGHT_POLL_INTERVAL = 0.2
INFLIGHT_WAIT_MAX = 5.0  # seconds

# -------------------------
# TLD and keyword lists
# -------------------------
HIGH_RISK_TLDS = {"xyz", "top", "tk", "ga", "ml", "cf"}
LOW_RISK_TLDS = {"cn", "ru", "info", "io", "cc", "im", "ai"}

# Palabras que indican credenciales / robo (alto riesgo) - estas se evalúan **en contexto de marca**
HIGH_CONF_PATH_KEYWORDS = {
    "login","signin","sign-in","sign_in","verify","verification","validate",
    "password","pwd","passwd","reset","reset-password","confirm","confirm-account",
    "account","secure","secure-login","auth","authentication","verify-account",
    "unlock","security-update","account-security","secure-access","access"
}

# Palabras promocionales (baja confianza, útiles para tiendas falsas)
PROMO_LOW_CONF_KEYWORDS = {
    "free","gratis","discount","descuento","sale","venta","oferta","ofertas",
    "promo","promocion","promoción","coupon","cupon","voucher","rebaja",
    "clearance","liquidacion","outlet","cheap","barato","deal","deals",
    "black friday","cyber monday","flash sale","super oferta"
}

URGENCY_KEYWORDS = {
    "limited","limited time","hurry","act now","last chance","expires","vence",
    "ahora","urgente","solo hoy","hoy","ultimo dia","último día","offer ends",
    "ends soon","aprovecha"
}

# Palabras que indican páginas educativas/reportes (no deben sumarse como indicadores)
ANTI_PHISHING_KEYWORDS = {
    "phishtank", "virustotal", "safe", "safe browsing", "blocklist",
    "threat", "security", "whois", "dnslytics", "urlscan", "opendns", "abuse",
    "phishing", "blacklist", "scam", "fake", "remove", "how", "learn",
    "tutorial", "guide", "awareness", "identify", "spot", "avoid", "warning",
    "beware", "alert", "faq", "support", "help", "report", "checker"
}

IRRELEVANT_KEYWORDS = {
    "forum", "reddit", "support", "help", "discussion", "community", "news",
    "blog", "faq", "wiki", "article", "post", "how to", "how-to", "tutorial",
    "guide", "fix", "hc/en-us", "articles", "forgotten", "parental", "linking"
}

IRRELEVANT_DOMAINS = {
    "reddit.com", "quora.com", "wikipedia.org", "medium.com",
    "stackoverflow.com", "youtube.com", "facebook.com", "instagram.com",
    "x.com", "tiktok.com", "amazon.com"
}

WHITELIST_DOMAINS = {
    'apple.com', 'microsoft.com', 'google.com', 'amazon.com', 'facebook.com'
}

WHITELIST_PATTERNS = [
    r'^([a-z0-9-]+\.)*[a-z0-9-]+\.(com|net)/?$',
    r'^([a-z0-9-]+\.)*[a-z0-9-]+\.(com|net)/(support|app|news|docs|community|blog|tickets|faq|about|store|products|account|login|kb|help|answers|rewards)/.*$'
]

# In-memory tracker para evitar WHOIS duplicadas simultaneas
_inflight = {}

# -------------------------
# Helpers
# -------------------------
def safe_list(value):
    """Normaliza un valor a list[str]."""
    if not value:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if v and str(v).strip()]
    return [str(value).strip()]

def normalize_date(d):
    """Normaliza fechas WHOIS a ISO si posible."""
    try:
        if isinstance(d, list):
            d = d[0] if d else None
        if isinstance(d, datetime):
            return d.isoformat()
        if isinstance(d, str):
            try:
                # intentar ISO primero
                return datetime.fromisoformat(d.replace("Z", "")).isoformat()
            except Exception:
                # probar algunos formatos comunes
                for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d", "%m/%d/%Y"):
                    try:
                        return datetime.strptime(d.split('.')[0], fmt).isoformat()
                    except Exception:
                        continue
                return d
        return str(d)
    except Exception as e:
        logger.warning(f"Error normalizando fecha {d}: {e}")
        return str(d)

def _is_domain_irrelevant(base_domain):
    if not base_domain:
        return False
    return any(base_domain.endswith(d) for d in IRRELEVANT_DOMAINS)

def _is_whitelist_match(base_domain, url):
    if not base_domain:
        return False
    if base_domain in WHITELIST_DOMAINS:
        return True
    for p in WHITELIST_PATTERNS:
        try:
            if re.search(p, url, re.IGNORECASE):
                return True
        except re.error:
            continue
    return False

def _cache_and_return(info_partial):
    """Normaliza, guarda en cache y devuelve la estructura esperada."""
    info = {
        "url": info_partial.get("url"),
        "domain": info_partial.get("domain"),
        "base_domain": info_partial.get("base_domain"),
        "title": info_partial.get("title", ""),
        "snippet": info_partial.get("snippet", ""),
        "filtered": info_partial.get("filtered", True),
        "reasons": info_partial.get("reasons", []),
        "score": info_partial.get("score", 0),
        "whitelisted": bool(info_partial.get("whitelisted", False)),
        "is_legit_subdomain": bool(info_partial.get("is_legit_subdomain", False)),
        "cached_at": info_partial.get("cached_at", datetime.now().isoformat()),
        "registrar": info_partial.get("registrar"),
        "creation_date": info_partial.get("creation_date"),
        "expiration_date": info_partial.get("expiration_date"),
        "country": info_partial.get("country"),
        "emails": info_partial.get("emails", []),
        "mx_records": info_partial.get("mx_records", []),
        "mx_count": info_partial.get("mx_count", 0),
        "ip": info_partial.get("ip", []),
        "ttl": info_partial.get("ttl"),
        "ns_records": info_partial.get("ns_records", []),
        "ns_count": info_partial.get("ns_count", 0),
        "error": info_partial.get("error")
    }
    try:
        save_domain_info(info)
    except Exception as e:
        logger.debug(f"Error guardando cache en _cache_and_return para {info.get('base_domain')}: {e}")
    return info

# -------------------------
# Core: WHOIS + DNS + cache
# -------------------------
def get_domain_info_with_cache(url, title="", snippet="", normalized_url=None):
    """
    Recupera WHOIS/DNS con caché. Devuelve un dict mínimo con campos listados abajo.
    """
    parsed = urlparse(url)
    host = (parsed.hostname or parsed.netloc or "").strip()
    extracted = tldextract.extract(host)
    if not extracted.suffix:
        base_domain = host.lower()
    else:
        base_domain = f"{extracted.domain}.{extracted.suffix}".lower()
    domain = host.lower()

    # intentar caché persistente
    try:
        cached_info = get_cached_domain_info(base_domain)
    except Exception as e:
        logger.debug(f"Error consultando caché para {base_domain}: {e}")
        cached_info = None

    if cached_info:
        # añadir contexto actual y devolver
        cached_info.update({
            "url": url,
            "title": title,
            "snippet": snippet,
            "normalized_url": normalized_url
        })
        logger.debug(f"Usando caché SQLite para {base_domain}")
        return cached_info

    text_all = " ".join([str(x or "") for x in (url, title, snippet)]).lower()

    # filtros rápidos: páginas educativas/reporte o irrelevantes
    if any(k in text_all for k in ANTI_PHISHING_KEYWORDS) or any(k in text_all for k in IRRELEVANT_KEYWORDS):
        logger.info(f"URL {url} filtrado por contenido irrelevante/educativo (title/snippet/url)")
        return _cache_and_return({
            "url": url, "domain": domain, "base_domain": base_domain,
            "title": title, "snippet": snippet,
            "filtered": True, "reasons": ["Irrelevant or educational content"],
            "score": 0, "whitelisted": True,
            "is_legit_subdomain": False,
            "cached_at": datetime.now().isoformat()
        })

    if _is_domain_irrelevant(base_domain):
        logger.info(f"URL descartado por dominio irrelevante: {url} (base_domain: {base_domain})")
        return _cache_and_return({
            "url": url, "domain": domain, "base_domain": base_domain,
            "title": title, "snippet": snippet,
            "filtered": True, "reasons": ["Irrelevant domain"],
            "score": 0, "whitelisted": True,
            "is_legit_subdomain": False,
            "cached_at": datetime.now().isoformat()
        })

    if _is_whitelist_match(base_domain, url):
        logger.info(f"URL {url} filtrado como seguro (whitelist) - {base_domain}")
        return _cache_and_return({
            "url": url, "domain": domain, "base_domain": base_domain,
            "title": title, "snippet": snippet,
            "filtered": True, "reasons": ["Whitelist match"],
            "score": 0, "whitelisted": True,
            "is_legit_subdomain": bool(re.search(r'^([a-z0-9-]+\.)+[a-z0-9-]+\.(com|net)(/.*)?$', url, re.IGNORECASE)),
            "cached_at": datetime.now().isoformat()
        })

    # inflight handling: si otro worker está consultando, espera un poquito y reusa cache si aparece
    if base_domain in _inflight:
        logger.debug(f"Esperando resultado inflight para {base_domain}")
        waited = 0.0
        while base_domain in _inflight and waited < INFLIGHT_WAIT_MAX:
            time.sleep(INFLIGHT_POLL_INTERVAL)
            waited += INFLIGHT_POLL_INTERVAL
            cached_later = get_cached_domain_info(base_domain)
            if cached_later:
                cached_later.update({"url": url, "title": title, "snippet": snippet, "normalized_url": normalized_url})
                logger.debug(f"Usando caché que apareció mientras esperaba para {base_domain}")
                return cached_later
        # si no apareció, seguimos y hacemos la consulta nosotros mismos

    _inflight[base_domain] = True
    try:
        logger.info(f"Consultando WHOIS para {base_domain}")
        try:
            w = whois.whois(base_domain)
        except Exception as e:
            logger.warning(f"whois.whois falló para {base_domain}: {e}")
            w = None

        info = {
            "url": url,
            "domain": domain,
            "base_domain": base_domain,
            "title": title,
            "snippet": snippet,
            "registrar": getattr(w, "registrar", None) if w else None,
            "creation_date": normalize_date(getattr(w, "creation_date", None)) if w else None,
            "expiration_date": normalize_date(getattr(w, "expiration_date", None)) if w else None,
            "country": getattr(w, "country", None) if w else None,
            "emails": safe_list(getattr(w, "emails", []) if w else []),
            "cached_at": datetime.now().isoformat(),
            "whitelisted": False,
            "is_legit_subdomain": bool(re.search(r'^([a-z0-9-]+\.)+[a-z0-9-]+\.(com|net)(/.*)?$', url, re.IGNORECASE)),
            "normalized_url": normalized_url
        }

        resolver = dns.resolver.Resolver()
        # intentar MX con resolvers públicos
        for ns_list in (['8.8.8.8'], ['1.1.1.1']):
            resolver.nameservers = ns_list
            try:
                mx_records = resolver.resolve(base_domain, 'MX', lifetime=5.0)
                info["mx_records"] = [str(rr.exchange).rstrip('.') for rr in mx_records]
                info["mx_count"] = len(mx_records)
                break
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                info.setdefault("mx_records", [])
                info.setdefault("mx_count", 0)
            except Exception as dns_e:
                logger.debug(f"Error MX con nameserver {ns_list}: {dns_e}")
                info.setdefault("mx_records", [])
                info.setdefault("mx_count", 0)

        try:
            a_records = resolver.resolve(base_domain, 'A', lifetime=5.0)
            info["ip"] = [str(rr) for rr in a_records]
            try:
                info["ttl"] = a_records.rrset.ttl if a_records.rrset is not None else None
            except Exception:
                info["ttl"] = None
        except Exception:
            info.setdefault("ip", [])
            info.setdefault("ttl", None)

        try:
            ns_records = resolver.resolve(base_domain, 'NS', lifetime=5.0)
            info["ns_records"] = [str(ns).rstrip('.') for ns in ns_records]
            info["ns_count"] = len(ns_records)
        except Exception:
            info.setdefault("ns_records", [])
            info.setdefault("ns_count", 0)

        # Guardar en cache persistente (sin score aún)
        try:
            save_domain_info(info)
        except Exception as e:
            logger.debug(f"Error guardando cache WHOIS para {base_domain}: {e}")

        return info

    except Exception as e:
        logger.error(f"Error en WHOIS/DNS para {url}: {e}")
        return _cache_and_return({
            "url": url,
            "domain": domain,
            "base_domain": base_domain,
            "title": title,
            "snippet": snippet,
            "error": str(e),
            "cached_at": datetime.now().isoformat(),
            "score": 50,
            "whitelisted": False,
            "is_legit_subdomain": False
        })
    finally:
        _inflight.pop(base_domain, None)

# -------------------------
# Scoring / heuristics (centrado en marcas)
# -------------------------
def is_suspicious(domain_info, brands=None, suspicious_threshold=SUSPICIOUS_THRESHOLD):
    """
    Evalúa si un dominio es sospechoso de phishing:
      - brands: lista de marcas (strings). Si se pasan, las coincidencias con marcas aumentan
                la prioridad y activan el conteo de keywords de alto riesgo.
      - devuelve (suspicious_bool, reasons_list, score_int)

    Estrategia clave para reducir falsos positivos:
      * NO contar keywords tipo 'login' por sí solas como indicador alto salvo que:
          - el dominio/título/snippet contenga una MENCION a la marca objetivo, o
          - ya existan señales fuertes WHOIS/DNS (p.ej. sin emails, TTL muy corto, TLD exótico)
      * Para phishing comercial (tiendas falsas): los keywords promocionales + mención de marca
        aumentan el score.
    """
    try:
        url = (domain_info.get("url") or "").strip()
        path = urlparse(url).path.lower()
        title = (domain_info.get("title") or "").lower()
        snippet = (domain_info.get("snippet") or "").lower()
        base_domain = (domain_info.get("base_domain") or "").lower()

        reasons = []
        score = 0
        strong_signal_present = False

        # normalizar tokens: base_domain + path + title + snippet
        tokens_all = set(re.split(r'[\s\-/\?&=_\.,:;!]+', f"{base_domain} {path} {title} {snippet}".lower()))
        tokens_all.discard("")  # quitar vacíos

        # 1) filtro por cached 'filtered'
        if domain_info.get("filtered"):
            logger.info(f"Dominio {base_domain} filtrado: {domain_info.get('reasons')}")
            return False, domain_info.get("reasons", []), 0

        # 2) WHOIS: edad del dominio
        creation_date = domain_info.get("creation_date")
        if creation_date and creation_date != "None":
            try:
                creation_dt = datetime.fromisoformat(creation_date.replace("Z", ""))
                age_days = (datetime.now() - creation_dt).days
                if age_days < CREATION_LESS_THAN_DAYS:
                    reasons.append(f"Creado hace {age_days} días (<{CREATION_LESS_THAN_DAYS})")
                    score += CREATION_WEIGHT
                    strong_signal_present = True
            except Exception:
                logger.debug(f"Formato fecha WHOIS inválido: {creation_date}")

        # 3) WHOIS fields: emails / registrar
        emails = domain_info.get("emails") or []
        if not emails:
            reasons.append("Sin emails en WHOIS")
            score += NO_EMAIL_WEIGHT
            strong_signal_present = True

        registrar = domain_info.get("registrar")
        if not registrar or (isinstance(registrar, str) and registrar.strip() == ""):
            reasons.append("Sin registrador confiable")
            score += NO_REGISTRAR_WEIGHT
            strong_signal_present = True

        # 4) TLD risk
        extracted = tldextract.extract(base_domain)
        tld = extracted.suffix.lower() if extracted.suffix else ""
        if tld in HIGH_RISK_TLDS:
            reasons.append(f"TLD de alto riesgo: .{tld}")
            score += HIGH_RISK_TLD_WEIGHT
            strong_signal_present = True
        elif tld in LOW_RISK_TLDS:
            reasons.append(f"TLD de riesgo medio: .{tld}")
            score += LOW_RISK_TLD_WEIGHT
            strong_signal_present = True

        # 5) DNS checks
        mx_count = domain_info.get("mx_count", 0)
        if mx_count == 0:
            reasons.append("Sin MX records")
            score += NO_MX_WEIGHT
            # no forzamos strong_signal aquí, pero es un indicador

        ttl = domain_info.get("ttl")
        try:
            if ttl is not None and int(ttl) < TTL_SHORT_SEC:
                reasons.append(f"TTL corto: {ttl}s")
                score += TTL_SHORT_WEIGHT
                strong_signal_present = True
        except Exception:
            pass

        ip_list = domain_info.get("ip") or []
        if not ip_list:
            reasons.append("No resuelve IP")
            score += NO_IP_WEIGHT
            strong_signal_present = True

        ns_count = domain_info.get("ns_count", 0)
        if ns_count <= 1:
            reasons.append("Pocos NS records")
            score += NS_FEW_WEIGHT
            strong_signal_present = True

        # nameservers confiables?
        ns_records = [ns.lower() for ns in domain_info.get("ns_records", []) or []]
        trusted_ns_keywords = ('cloudflare', 'awsdns', 'googledomains', 'akam', 'fastly', 'dnsmadeeasy', 'nsone', 'rackspace', 'dnsimple', 'verisign', 'godaddy', 'namecheap')
        if ns_records and not any(any(t in ns for t in trusted_ns_keywords) for ns in ns_records):
            reasons.append("Nameservers no confiables")
            score += UNTRUSTED_NS_WEIGHT

        if isinstance(ip_list, list) and len(ip_list) > 5:
            reasons.append("Múltiples IPs (fast-flux?)")
            score += MULTIPLE_IPS_WEIGHT
            strong_signal_present = True

        # 6) HTTPS
        if not url.lower().startswith("https"):
            reasons.append("Sin HTTPS")
            score += HTTPS_MISSING_WEIGHT
            strong_signal_present = True

        # ----------------------------
        # 7) Detección orientada a MARCAS (brands)
        # ----------------------------
        # Si se pasan brands (lista de strings), comparamos tokens y frases simples.
        brand_matches = set()
        brand_token_matches = set()
        brands_list = []
        if brands:
            # normalizar marcas a tokens (simple split en espacios y lower)
            for b in brands:
                if not b:
                    continue
                brands_list.append(b.strip().lower())
            # buscar coincidencias exactas o tokens
            for b in brands_list:
                if b in base_domain or b in title or b in snippet or b in path:
                    brand_matches.add(b)
                # token match: check tokens intersection
                b_tokens = set(re.split(r'[\s\-/\._]+', b))
                if b_tokens & tokens_all:
                    brand_token_matches.add(b)
        # count brand presence
        brand_present = bool(brand_matches or brand_token_matches)

        # ----------------------------
        # 8) High-confidence keywords (credential theft)
        # ----------------------------
        # Regla importante para reducir falsos positivos:
        #  - Si NO hay brands, entonces estas keywords solo cuentan significativamente
        #    cuando existan señales fuertes (WHOIS/DNS) o el dominio es similar a una marca conocida.
        #  - Si HAY brands y el brand aparece en title/snippet/path/domain -> keywords tienen mucho más peso.
        hc_found = HIGH_CONF_PATH_KEYWORDS.intersection(tokens_all)
        hc_count = len(hc_found)

        if hc_count > 0:
            # determinar factor de contexto
            if brand_present:
                # si la marca aparece, dar boost
                added = (HIGH_CONF_BASE + HIGH_CONF_BRAND_BOOST) * hc_count
                reasons.append(f"Keywords de alta confianza (contexto marca): {', '.join(sorted(hc_found))}")
                score += added
                strong_signal_present = True
            else:
                # sin marca, solo sumar si strong signals already present (o si domain nombrado es obvio typosquatting)
                if strong_signal_present:
                    added = HIGH_CONF_BASE * hc_count
                    reasons.append(f"Keywords de alta confianza (con señales fuertes): {', '.join(sorted(hc_found))}")
                    score += added
                else:
                    # muy conservador: sumar poco para no false positive
                    score += max(1, HIGH_CONF_BASE // 4) * hc_count
                    reasons.append(f"Keywords de alta confianza (aisladas): {', '.join(sorted(hc_found))}")

        # ----------------------------
        # 9) Promotional keywords (ecommerce phishing)
        # ----------------------------
        promo_found = PROMO_LOW_CONF_KEYWORDS.intersection(tokens_all)
        if promo_found:
            # si aparece la marca con promos -> serio
            if brand_present:
                score += LOW_PROMO_WEIGHT * len(promo_found) * 2
                reasons.append(f"Keywords promocionales junto a marca: {', '.join(sorted(promo_found))}")
            elif strong_signal_present:
                score += LOW_PROMO_WEIGHT * len(promo_found)
                reasons.append(f"Keywords promocionales con señales fuertes: {', '.join(sorted(promo_found))}")
            else:
                # aisladas -> sumar muy poco
                score += LOW_PROMO_WEIGHT
                reasons.append(f"Keywords promocionales aisladas: {', '.join(sorted(promo_found))}")

        # ----------------------------
        # 10) Urgency keywords
        # ----------------------------
        urgency_found = URGENCY_KEYWORDS.intersection(tokens_all)
        if urgency_found:
            if brand_present or strong_signal_present or promo_found:
                score += URGENCY_WEIGHT * len(urgency_found)
                reasons.append(f"Keywords urgencia: {', '.join(sorted(urgency_found))}")
            else:
                # poco peso si aisladas
                score += max(1, URGENCY_WEIGHT // 2)

        # ----------------------------
        # 11) Typosquatting / similitud con marcas conocidas (global known brands list)
        # ----------------------------
        KNOWN_DOMAINS_SIM = [
            'paypal.com','apple.com','microsoft.com','google.com','amazon.com',
            'facebook.com','twitter.com','netflix.com','bankofamerica.com','chase.com'
        ]
        for known in KNOWN_DOMAINS_SIM:
            if not base_domain:
                continue
            # evitar comparar dominios demasiado distintos en longitud
            if abs(len(base_domain) - len(known)) > 6:
                continue
            try:
                levenshtein_dist = distance(base_domain, known)
                maxlen = max(len(base_domain), len(known)) or 1
                levenshtein_similarity = 1 - (levenshtein_dist / maxlen)
                jaro_similarity = jaro_winkler(base_domain, known)
                if levenshtein_similarity > 0.9 or jaro_similarity > 0.95:
                    reasons.append(f"Similar a {known} (typosquatting posible)")
                    score += SIMILAR_DOMAIN_WEIGHT
                    strong_signal_present = True
            except Exception:
                logger.debug(f"Error comparando similitud con {known}")

        # ----------------------------
        # 12) Subdominios sospechosos
        # ----------------------------
        try:
            subparts = (domain_info.get("domain") or "").split('.')
            if len(subparts) > 3:
                subdomain_str = '.'.join(subparts[:-2])
                if any(p in subdomain_str for p in ("login", "secure", "account", "verify")):
                    reasons.append(f"Subdominio sospechoso: {subdomain_str}")
                    score += 8
                    strong_signal_present = True
        except Exception:
            pass

        # ----------------------------
        # Decisión final
        # ----------------------------
        score = min(int(score), 100)
        # Para ser sospechoso necesitamos:
        #  - score >= threshold, o
        #  - strong_signal_present + brand_present (caso de credential phishing dirigido a marca)
        suspicious = False
        if score >= suspicious_threshold:
            suspicious = True
        elif strong_signal_present and brand_present:
            # si hay señales fuertes y la marca aparece -> sospechoso
            suspicious = True
            reasons.append("Señales fuertes combinadas con mención de marca")

        # Guardar score/reasons en la cache persistente (para post-mortem)
        domain_info_to_save = dict(domain_info) if isinstance(domain_info, dict) else {}
        domain_info_to_save.update({
            "reasons": reasons,
            "score": score,
            "filtered": domain_info.get("filtered", False),
            "whitelisted": domain_info.get("whitelisted", False),
            "cached_at": domain_info.get("cached_at", datetime.now().isoformat())
        })
        try:
            save_domain_info(domain_info_to_save)
        except Exception as e:
            logger.debug(f"No se pudo guardar score/reasons en cache para {base_domain}: {e}")

        if suspicious:
            logger.info(f"Dominio {base_domain} sospechoso: {', '.join(reasons)} (score: {score})")
        else:
            logger.debug(f"Dominio {base_domain} NO sospechoso (score: {score}). Razones: {reasons}")

        return suspicious, reasons, score

    except Exception as e:
        logger.exception(f"Error evaluando {domain_info.get('base_domain','?')}: {e}")
        return True, ["Error en evaluación"], 50
