# whois_lookup.py
import whois
from urllib.parse import urlparse
from datetime import datetime
import logging
import re
import dns.resolver
from Levenshtein import jaro_winkler, distance
import tldextract

from database import get_cached_domain_info, save_domain_info

logging.basicConfig(
    filename="app.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

SUSPICIOUS_TLDS = {"xyz", "top", "cn", "ru", "info", "io", "cc", "tk", "ga", "ml", "im", "ai"}
SUSPICIOUS_PATH_KEYWORDS = ["login", "account", "verify", "signin", "sign-in", "secure", "auth", "password", "update", "rewards"]
IRRELEVANT_KEYWORDS = ["forum", "reddit", "support", "help", "discussion", "community", "news", "blog", "faq", "wiki", "article", "post"]
IRRELEVANT_DOMAINS = {
    "reddit.com", "quora.com", "wikipedia.org", "medium.com", "stackoverflow.com",
    "youtube.com", "facebook.com", "instagram.com", "x.com", "tiktok.com"
}
WHITELIST_DOMAINS = {
    'apple.com', 'microsoft.com', 'google.com', 'amazon.com', 'facebook.com',
    # ... mantiene la lista
}
WHITELIST_PATTERNS = [
    r'^([a-z0-9-]+\.)*[a-z0-9-]+\.(com|net)/?$',
    r'^([a-z0-9-]+\.)*[a-z0-9-]+\.(com|net)/(support|app|news|docs|community|blog|tickets|faq|about|store|products|account|login|kb|help|answers|rewards)/.*$',
    r'^(support|kb|app|docs|www|login|account|m|shop|store|en|es)\.[a-z0-9-]+\.(com|net)/.*$'
]

# In-memory tracker para evitar llamadas WHOIS duplicadas simultáneas
_inflight = {}

def normalize_date(d):
    try:
        if isinstance(d, list):
            d = d[0]
        if isinstance(d, datetime):
            return d.isoformat()
        if isinstance(d, str):
            # intenta parsear ISO u otros formatos comunes
            try:
                return datetime.fromisoformat(d.replace("Z", "")).isoformat()
            except Exception:
                return d
        return str(d)
    except Exception as e:
        logging.warning(f"Error normalizando fecha {d}: {e}")
        return str(d)

def get_domain_info_with_cache(url, title="", snippet="", normalized_url=None):
    """Obtiene WHOIS y DNS con caché en SQLite, usando dominio base como clave."""
    parsed = urlparse(url)
    extracted = tldextract.extract(parsed.netloc)
    base_domain = f"{extracted.domain}.{extracted.suffix}".lower()
    domain = parsed.netloc.replace("www.", "").lower()

    # Primero intenta caché persistente
    cached_info = get_cached_domain_info(base_domain)
    if cached_info:
        # añadimos contexto de url/title/snippet/normalized_url y devolvemos
        cached_info.update({
            "url": url,
            "title": title,
            "snippet": snippet,
            "normalized_url": normalized_url
        })
        logging.debug(f"Información cacheada encontrada para {base_domain}")
        return cached_info

    # Filtros rápidos por lista de dominios irrelevantes
    if any(d in base_domain for d in IRRELEVANT_DOMAINS):
        logging.info(f"URL descartado por dominio irrelevante: {url} (base_domain: {base_domain})")
        info = {
            "url": url,
            "domain": domain,
            "base_domain": base_domain,
            "title": title,
            "snippet": snippet,
            "filtered": True,
            "reasons": ["Irrelevant domain"],
            "score": 0,
            "whitelisted": True,
            "is_legit_subdomain": False,
            "cached_at": datetime.now().isoformat(),
            "normalized_url": normalized_url
        }
        save_domain_info(info)
        return info

    # Filtro de contenido irrelevante por title/snippet/url
    title_lower = title.lower() if title else ""
    snippet_lower = snippet.lower() if snippet else ""
    url_lower = url.lower()
    if any(keyword in title_lower or keyword in snippet_lower or keyword in url_lower
           for keyword in IRRELEVANT_KEYWORDS):
        logging.info(f"URL {url} filtrado como irrelevante (title/snippet/url)")
        info = {
            "url": url,
            "domain": domain,
            "base_domain": base_domain,
            "title": title,
            "snippet": snippet,
            "filtered": True,
            "reasons": ["Irrelevant content"],
            "score": 0,
            "whitelisted": True,
            "is_legit_subdomain": False,
            "cached_at": datetime.now().isoformat(),
            "normalized_url": normalized_url
        }
        save_domain_info(info)
        return info

    # Filtro whitelist
    is_legit_subdomain = bool(re.search(r'^([a-z0-9-]+\.)+[a-z0-9-]+\.(com|net)(/.*)?$', url, re.IGNORECASE))
    if (base_domain in WHITELIST_DOMAINS or any(re.search(p, url, re.IGNORECASE) for p in WHITELIST_PATTERNS)):
        logging.info(f"URL {url} filtrado como seguro (whitelist, base_domain: {base_domain})")
        info = {
            "url": url,
            "domain": domain,
            "base_domain": base_domain,
            "title": title,
            "snippet": snippet,
            "filtered": True,
            "reasons": ["Whitelist match"],
            "score": 0,
            "whitelisted": True,
            "is_legit_subdomain": is_legit_subdomain,
            "cached_at": datetime.now().isoformat(),
            "normalized_url": normalized_url
        }
        save_domain_info(info)
        return info

    # Evitar llamadas WHOIS duplicadas concurrenetes
    if base_domain in _inflight:
        logging.debug(f"Esperando resultado inflight para {base_domain}")
        # Espera activa corta: simplemente devolvemos lo que haya en cache si aparece después de X intentos.
        # Para simplicidad, devolvemos marcador y se reintentará posteriormente.
        return {
            "url": url,
            "domain": domain,
            "base_domain": base_domain,
            "title": title,
            "snippet": snippet,
            "filtered": False,
            "reasons": [],
            "cached_at": datetime.now().isoformat(),
            "whitelisted": False,
            "is_legit_subdomain": is_legit_subdomain,
            "normalized_url": normalized_url
        }

    _inflight[base_domain] = True
    try:
        logging.info(f"Consultando WHOIS para {base_domain}")
        w = whois.whois(base_domain)
        info = {
            "url": url,
            "domain": domain,
            "base_domain": base_domain,
            "title": title,
            "snippet": snippet,
            "registrar": w.registrar if getattr(w, "registrar", None) else None,
            "creation_date": normalize_date(getattr(w, "creation_date", None)),
            "expiration_date": normalize_date(getattr(w, "expiration_date", None)),
            "country": getattr(w, "country", None),
            "emails": w.emails if isinstance(getattr(w, "emails", None), list) else ([w.emails] if getattr(w, "emails", None) else []),
            "cached_at": datetime.now().isoformat(),
            "whitelisted": False,
            "is_legit_subdomain": is_legit_subdomain,
            "normalized_url": normalized_url
        }

        # DNS checks (con fallbacks)
        resolver = dns.resolver.Resolver()
        for ns in (['8.8.8.8'], ['1.1.1.1']):
            resolver.nameservers = ns
            try:
                mx_records = resolver.resolve(base_domain, 'MX')
                info["mx_records"] = [str(rr.exchange).rstrip('.') for rr in mx_records]
                info["mx_count"] = len(mx_records)
                break
            except Exception:
                info.setdefault("mx_records", [])
                info.setdefault("mx_count", 0)
        try:
            a_records = resolver.resolve(base_domain, 'A')
            info["ip"] = [str(rr) for rr in a_records]
            info["ttl"] = a_records.rrset.ttl if a_records.rrset is not None else None
        except Exception:
            info.setdefault("ip", [])
            info.setdefault("ttl", None)
        try:
            ns_records = resolver.resolve(base_domain, 'NS')
            info["ns_records"] = [str(ns).rstrip('.') for ns in ns_records]
            info["ns_count"] = len(ns_records)
        except Exception:
            info.setdefault("ns_records", [])
            info.setdefault("ns_count", 0)

        save_domain_info(info)
        return info
    except Exception as e:
        logging.error(f"Error en WHOIS para {url}: {e}")
        info = {
            "url": url,
            "domain": domain,
            "base_domain": base_domain,
            "title": title,
            "snippet": snippet,
            "error": str(e),
            "cached_at": datetime.now().isoformat(),
            "score": 50,
            "whitelisted": False,
            "is_legit_subdomain": is_legit_subdomain,
            "normalized_url": normalized_url
        }
        save_domain_info(info)
        return info
    finally:
        _inflight.pop(base_domain, None)

def is_suspicious(domain_info):
    """Evalúa probabilidades de phishing sobre la base de domain_info."""
    reasons = []
    score = 0
    try:
        if domain_info.get("filtered"):
            logging.info(f"Dominio {domain_info.get('base_domain')} filtrado: {domain_info.get('reasons')}")
            return False, domain_info.get("reasons", []), 0

        creation_date = domain_info.get("creation_date")
        if creation_date and creation_date != "None":
            try:
                creation_date_dt = datetime.fromisoformat(creation_date.replace("Z", ""))
                if (datetime.now() - creation_date_dt).days < 180:
                    reasons.append("Creado hace menos de 6 meses")
                    score += 25
            except Exception:
                logging.warning(f"Formato de fecha inválido: {creation_date}")

        if not domain_info.get("emails"):
            reasons.append("Sin emails en WHOIS")
            score += 20
        if not domain_info.get("registrar"):
            reasons.append("Sin registrador confiable")
            score += 20

        extracted = tldextract.extract(domain_info.get("base_domain", ""))
        if extracted.suffix and extracted.suffix.lower() in SUSPICIOUS_TLDS:
            reasons.append(f"TLD sospechoso: {extracted.suffix}")
            score += 40

        # DNS checks
        if domain_info.get("mx_count", 0) == 0:
            reasons.append("Sin MX records")
            score += 20
        ttl = domain_info.get("ttl")
        if ttl is not None and ttl < 3600:
            reasons.append(f"TTL corto: {ttl}s")
            score += 15
        if not domain_info.get("ip"):
            reasons.append("No resuelve IP")
            score += 20
        if domain_info.get("ns_count", 0) <= 1:
            reasons.append("Pocos NS records")
            score += 15

        trusted_ns = ('cloudflare.com', 'amazonaws.com', 'googledomains.com', 'akamai.net')
        ns_records = domain_info.get("ns_records", [])
        if ns_records and not any(any(ns.endswith(t) for t in trusted_ns) for ns in ns_records):
            reasons.append("Nameservers no confiables")
            score += 15
        if len(domain_info.get("ip", [])) > 5:
            reasons.append("Múltiples IPs sospechosas")
            score += 10

        # Similitud a dominios conocidos
        base_domain = domain_info.get("base_domain", "")
        KNOWN_DOMAINS = [
            'paypal.com', 'apple.com', 'microsoft.com', 'google.com', 'amazon.com',
            'facebook.com', 'twitter.com', 'netflix.com', 'bankofamerica.com', 'chase.com'
        ]
        for known in KNOWN_DOMAINS:
            levenshtein_dist = distance(base_domain, known)
            maxlen = max(len(base_domain), len(known)) or 1
            levenshtein_similarity = 1 - (levenshtein_dist / maxlen)
            jaro_similarity = jaro_winkler(base_domain, known)
            if (levenshtein_similarity > 0.9 or jaro_similarity > 0.95) and base_domain != known:
                reasons.append(f"Similar a {known} (Levenshtein: {levenshtein_similarity:.2f}, Jaro-Winkler: {jaro_similarity:.2f})")
                score += 30

        # Keywords sospechosos en path/title/snippet
        if not domain_info.get("whitelisted") and not domain_info.get("is_legit_subdomain"):
            path = urlparse(domain_info.get("url", "")).path.lower()
            tokens = re.split(r'[/?&\-_\.]', path)
            for keyword in SUSPICIOUS_PATH_KEYWORDS:
                if any(keyword in token for token in tokens):
                    reasons.append(f"Keyword sospechoso en path: {keyword}")
                    score += 5

            title = domain_info.get("title", "").lower()
            snippet = domain_info.get("snippet", "").lower()
            suspicious_content_keywords = ["login", "verify", "password", "signin", "auth", "secure", "account", "update", "scam", "fake"]
            for keyword in suspicious_content_keywords:
                if keyword in title:
                    reasons.append(f"Keyword sospechoso en title: {keyword}")
                    score += 5
                if keyword in snippet:
                    reasons.append(f"Keyword sospechoso en snippet: {keyword}")
                    score += 5

        # HTTPS check
        if not domain_info.get("url", "").startswith("https"):
            reasons.append("Sin HTTPS")
            score += 15

        score = min(score, 100)
        suspicious = score > 50
        if suspicious:
            logging.info(f"Dominio {base_domain} sospechoso: {', '.join(reasons)}, score: {score}")
        else:
            logging.info(f"Dominio {base_domain} no sospechoso, score: {score}")
        return suspicious, reasons, score
    except Exception as e:
        logging.error(f"Error evaluando {domain_info.get('base_domain', 'desconocido')}: {e}")
        return True, ["Error en evaluación"], 50
