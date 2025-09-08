# search.py
from ddgs import DDGS
import logging
from urllib.parse import urlparse, urlunparse
import tldextract
import time
import backoff

logging.basicConfig(
    filename="app.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

ALLOWED_TLDS = {
    "com", "net", "io", "cc", "im", "ai", "cn",
    "ru", "info", "tk", "ga", "ml", "xyz", "top", "co",
    "me", "biz", "co.uk", "in", "su", "gg"
}

def normalize_url(url):
    """Normaliza URLs para evitar duplicados (quitar www., usar https, normalizar path)."""
    parsed = urlparse(url)
    netloc = parsed.netloc.lower()
    if netloc.startswith("www."):
        netloc = netloc[4:]
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        scheme = "https"
    # Normalizamos path: eliminar trailing slash, remover fragment, queries opcionalmente
    path = parsed.path.rstrip("/")
    if path == "":
        path = "/"
    normalized = urlunparse((scheme, netloc, path, "", "", ""))
    logging.debug(f"Normalizando URL: {url} -> {normalized}")
    return normalized

@backoff.on_exception(backoff.expo, Exception, max_tries=3)
def search_urls(keyword, max_results=5):
    results_list = []
    seen_urls = set()
    try:
        refined_query = f'{keyword} (login OR account OR verify OR signin OR scam OR fake) -reddit -quora -wikipedia -forum -community'
        logging.info(f"Iniciando búsqueda refinada: {refined_query}")
        with DDGS() as ddgs:
            results = ddgs.text(refined_query, max_results=max_results)
            for r in results:
                if "href" not in r:
                    continue
                url = r["href"]
                try:
                    parsed = urlparse(url)
                    if not parsed.netloc:
                        continue
                    extracted = tldextract.extract(parsed.netloc)
                    if not extracted.suffix:
                        continue
                    base_domain = f"{extracted.domain}.{extracted.suffix}".lower()
                    suffix = extracted.suffix.lower()
                    if suffix not in ALLOWED_TLDS:
                        logging.info(f"URL descartado por TLD no permitido: {url} (suffix: {suffix})")
                        continue
                    normalized_url = normalize_url(url)
                    if normalized_url in seen_urls:
                        logging.info(f"URL duplicado descartado: {url} (Normalized: {normalized_url})")
                        continue
                    seen_urls.add(normalized_url)
                    title = r.get("title", "") or "No title available"
                    snippet = r.get("body", "") or "No snippet available"
                    results_list.append({
                        "original_url": url,
                        "normalized_url": normalized_url,
                        "title": title,
                        "snippet": snippet
                    })
                    logging.info(f"Encontrado URL: {url} | Normalized: {normalized_url}")
                except Exception as e:
                    logging.debug(f"Error procesando result {r}: {e}")
            time.sleep(1)
        logging.info(f"Total URLs únicos encontrados para {keyword}: {len(results_list)}")
        return results_list
    except Exception as e:
        logging.error(f"Error al buscar {keyword}: {e}")
        return []
