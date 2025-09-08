# main.py
from search import search_urls, normalize_url
from whois_lookup import get_domain_info_with_cache, is_suspicious
from database import init_db, save_result, get_suspicious_results, get_processed_urls
import pandas as pd
import logging

logging.basicConfig(
    filename="app.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def run_pipeline(keywords, max_results=5, output_file="phishing_report.csv", only_suspicious=False, score_threshold=50):
    init_db()  # Inicializa bases de datos
    results = []
    processed = get_processed_urls()  # normalized_url -> base_domain
    seen_normalized = set(processed.keys())

    for keyword in keywords:
        print(f"\nBuscando sitios para: {keyword}")
        logging.info(f"Procesando keyword: {keyword}")
        search_results = search_urls(keyword, max_results=max_results)
        if not search_results:
            print(f"    No se encontraron URLs para {keyword}")
            continue
        for item in search_results:
            url = item["original_url"]
            normalized_url = item["normalized_url"]
            if normalized_url in seen_normalized:
                logging.info(f"URL duplicado omitido (ya procesado): {url} (Normalized: {normalized_url})")
                continue
            seen_normalized.add(normalized_url)
            title = item.get("title", "No title available")
            snippet = item.get("snippet", "No snippet available")
            print(f"   ➜ Analizando {url}")
            logging.info(f"Analizando URL: {url} | Normalized: {normalized_url} | Title: {title}")
            info = get_domain_info_with_cache(url, title=title, snippet=snippet, normalized_url=normalized_url)
            info["keyword"] = keyword
            suspicious, reasons, score = is_suspicious(info)
            result = {
                "keyword": keyword,
                "url": url,
                "normalized_url": normalized_url,
                "base_domain": info.get("base_domain", ""),
                "title": title,
                "snippet": snippet,
                "suspicious": suspicious,
                "reasons": ", ".join(reasons) if reasons else "None",
                "score": score,
                "whitelisted": info.get("whitelisted", False),
                "is_legit_subdomain": info.get("is_legit_subdomain", False),
                "registrar": info.get("registrar"),
                "creation_date": info.get("creation_date"),
                "expiration_date": info.get("expiration_date"),
                "country": info.get("country"),
                "emails": info.get("emails", []),
                "mx_records": info.get("mx_records", []),
                "mx_count": info.get("mx_count", 0),
                "ip": info.get("ip", []),
                "ttl": info.get("ttl"),
                "ns_records": info.get("ns_records", []),
                "ns_count": info.get("ns_count", 0)
            }
            results.append(result)
            save_result(result)
            print(f"    URL procesado: {url} (Suspicious: {suspicious}, Score: {score})")
            logging.info(f"URL {url} añadido al reporte: Suspicious={suspicious}, Score={score}")

    df = pd.DataFrame(results)
    df.to_csv(output_file, index=False)
    print(f"\nReporte generado: {output_file} (entradas: {len(results)})")
    logging.info(f"Reporte generado: {output_file} con {len(results)} entradas")

    suspicious_results = get_suspicious_results(score_threshold)
    if suspicious_results:
        print(f"\nResultados sospechosos (score >= {score_threshold}):")
        for res in suspicious_results:
            print(f"  - {res['url']} (Score: {res['score']}, Razones: {res['reasons']})")
    else:
        print(f"\nNo se encontraron resultados sospechosos con score >= {score_threshold}")

    return results

if __name__ == "__main__":
    keywords = ["nike", "adidas", "thenorthface"]
    run_pipeline(keywords, max_results=5, only_suspicious=False)
