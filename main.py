import logging
import time
from typing import List, Dict, Any
from urllib.parse import urlparse

from database import init_db, save_result, get_processed_urls, export_results_to_csv, get_suspicious_results
from whois_lookup import get_domain_info_with_cache, is_suspicious
from search import search_urls_parallel, normalize_url  # Cambiado a search_urls_parallel

# ================================
# Configuración de logging
# ================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(name)s - %(message)s"
)
logger = logging.getLogger(__name__)

# ================================
# Funciones principales
# ================================

def process_item(item: Dict[str, Any], keyword: str, processed_urls: set) -> Dict[str, Any] | None:
    url = item.get("original_url")
    title = item.get("title", "")
    snippet = item.get("snippet", "")

    if not url:
        return None

    normalized = normalize_url(url)
    if normalized in processed_urls:
        logger.debug(f"Saltando URL ya procesada: {normalized}")
        return None

    domain_info = get_domain_info_with_cache(url, title=title, snippet=snippet)
    suspicious, reasons_list, score = is_suspicious(domain_info)

    result = {
        "keyword": keyword,
        "url": url,
        "normalized_url": normalized,
        "domain": domain_info.get("base_domain", "") or "",
        "title": title,
        "snippet": snippet,
        "suspicious": suspicious,
        "reasons": reasons_list,
        "score": int(score or 0),
        "whitelisted": bool(domain_info.get("whitelisted", False)),
        "is_legit_subdomain": bool(domain_info.get("is_legit_subdomain", False)),
        "registrar": domain_info.get("registrar"),
        "creation_date": domain_info.get("creation_date"),
        "expiration_date": domain_info.get("expiration_date"),
        "country": domain_info.get("country"),
        "emails": domain_info.get("emails", []),
        "mx_records": domain_info.get("mx_records", []),
        "mx_count": int(domain_info.get("mx_count", 0) or 0),
        "ip": domain_info.get("ip", []),
        "ttl": domain_info.get("ttl"),
        "ns_records": domain_info.get("ns_records", []),
        "ns_count": int(domain_info.get("ns_count", 0) or 0)
    }

    save_result(result)
    processed_urls.add(normalized)
    return result

def run_pipeline(keywords: List[str], max_results: int = 200) -> List[Dict[str, Any]]:
    init_db()
    processed_urls = set(get_processed_urls())
    suspicious_results = []

    for keyword in keywords:
        logger.info(f"Buscando: {keyword}")
        try:
            # ---------------------------
            # Aquí usamos motores paralelos
            # ---------------------------
            serp_results = search_urls_parallel(
                keyword,
                max_results=max_results,
                search_type="credentials",
                keep_query=False,
                rate_limit_seconds=1.0
            )
        except Exception:
            logger.exception(f"Error buscando URLs para: {keyword}")
            continue

        if not serp_results:
            logger.warning(f"No se encontraron resultados para: {keyword}")
            continue

        for item in serp_results:
            try:
                res = process_item(item, keyword, processed_urls)
                if res and res["suspicious"]:
                    suspicious_results.append(res)
            except Exception:
                logger.exception(f"Error procesando item: {item}")

        time.sleep(1)
        _write_csv_checkpoint("phishing_report.csv")

    try:
        export_results_to_csv("results_full.csv")
        logger.info("Exportación completa de la DB a results_full.csv")
    except Exception:
        logger.exception("Error exportando resultados completos")

    return suspicious_results

def _write_csv_checkpoint(path: str):
    try:
        suspicious = get_suspicious_results()
        if suspicious:
            import csv
            keys = suspicious[0].keys()
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=keys)
                writer.writeheader()
                writer.writerows(suspicious)
            logger.info(f"CSV incremental exportado: {path} ({len(suspicious)} filas)")
        else:
            logger.info("No hay resultados sospechosos para exportar en CSV incremental")
    except Exception:
        logger.exception("Error exportando CSV incremental")

# ================================
# Ejecución directa
# ================================
if __name__ == "__main__":
    keywords = ["adidas", "harley davidson"]
    results = run_pipeline(keywords, max_results=500) 

    logger.info(f"Pipeline finalizado — resultados sospechosos: {len(results)}")
    for r in results:
        logger.info(
            f"- {r['url']} (Score: {r['score']}, Razones: {r['reasons']})"
        )
