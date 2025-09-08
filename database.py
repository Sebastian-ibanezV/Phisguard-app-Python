# database.py
import sqlite3
import json
from datetime import datetime, timedelta
import logging

logging.basicConfig(
    filename="app.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

DB_WHOIS = "whois_cache.db"
DB_RESULTS = "phishing_results.db"


def init_db():
    """Inicializa las bases de datos SQLite para caché WHOIS y resultados."""
    try:
        # Base de datos WHOIS
        conn = sqlite3.connect(DB_WHOIS)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS domain_info (
                base_domain TEXT PRIMARY KEY,
                url TEXT,
                domain TEXT,
                title TEXT,
                snippet TEXT,
                registrar TEXT,
                creation_date TEXT,
                expiration_date TEXT,
                country TEXT,
                emails TEXT,
                mx_records TEXT,
                mx_count INTEGER,
                ip TEXT,
                ttl INTEGER,
                ns_records TEXT,
                ns_count INTEGER,
                filtered BOOLEAN,
                reasons TEXT,
                score INTEGER,
                whitelisted BOOLEAN,
                is_legit_subdomain BOOLEAN,
                cached_at TEXT,
                error TEXT
            )
        """)
        conn.commit()
        conn.close()

        # Base de datos resultados phishing
        conn = sqlite3.connect(DB_RESULTS)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS phishing_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                keyword TEXT,
                url TEXT,
                normalized_url TEXT UNIQUE,
                base_domain TEXT,
                title TEXT,
                snippet TEXT,
                suspicious BOOLEAN,
                reasons TEXT,
                score INTEGER,
                whitelisted BOOLEAN,
                is_legit_subdomain BOOLEAN,
                registrar TEXT,
                creation_date TEXT,
                expiration_date TEXT,
                country TEXT,
                emails TEXT,
                mx_records TEXT,
                mx_count INTEGER,
                ip TEXT,
                ttl INTEGER,
                ns_records TEXT,
                ns_count INTEGER
            )
        """)
        # Índice adicional para búsquedas rápidas por normalized_url
        cursor.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_normalized_url
            ON phishing_results(normalized_url)
        """)
        conn.commit()
        conn.close()

        logging.info("Bases de datos SQLite inicializadas correctamente.")
    except Exception as e:
        logging.error(f"Error inicializando bases de datos: {e}")


def _row_to_domain_info(row):
    if not row:
        return None
    return {
        "base_domain": row[0],
        "url": row[1],
        "domain": row[2],
        "title": row[3],
        "snippet": row[4],
        "registrar": row[5],
        "creation_date": row[6],
        "expiration_date": row[7],
        "country": row[8],
        "emails": json.loads(row[9]) if row[9] else [],
        "mx_records": json.loads(row[10]) if row[10] else [],
        "mx_count": row[11],
        "ip": json.loads(row[12]) if row[12] else [],
        "ttl": row[13],
        "ns_records": json.loads(row[14]) if row[14] else [],
        "ns_count": row[15],
        "filtered": bool(row[16]),
        "reasons": json.loads(row[17]) if row[17] else [],
        "score": row[18],
        "whitelisted": bool(row[19]),
        "is_legit_subdomain": bool(row[20]),
        "cached_at": row[21],
        "error": row[22]
    }


def get_cached_domain_info(base_domain, cache_expiry_days=90):
    """Recupera información de dominio desde el caché SQLite. Evalúa expiración en Python."""
    try:
        conn = sqlite3.connect(DB_WHOIS)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM domain_info WHERE base_domain = ?", (base_domain,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            logging.debug(f"No cache record for {base_domain}")
            return None
        info = _row_to_domain_info(row)
        try:
            cached_at = datetime.fromisoformat(info["cached_at"])
            if cached_at >= datetime.now() - timedelta(days=cache_expiry_days):
                logging.info(f"Usando caché SQLite para {base_domain}")
                return info
            else:
                logging.debug(f"Caché expirado para {base_domain}")
                return None
        except Exception as e:
            logging.warning(f"Error parseando cached_at para {base_domain}: {e}")
            return None
    except Exception as e:
        logging.error(f"Error al consultar caché para {base_domain}: {e}")
        return None


def save_domain_info(info):
    """Guarda información de dominio en el caché SQLite."""
    try:
        conn = sqlite3.connect(DB_WHOIS)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO domain_info (
                base_domain, url, domain, title, snippet, registrar, creation_date, 
                expiration_date, country, emails, mx_records, mx_count, ip, ttl, 
                ns_records, ns_count, filtered, reasons, score, whitelisted, 
                is_legit_subdomain, cached_at, error
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            info.get("base_domain"),
            info.get("url"),
            info.get("domain"),
            info.get("title"),
            info.get("snippet"),
            info.get("registrar"),
            info.get("creation_date"),
            info.get("expiration_date"),
            info.get("country"),
            json.dumps(info.get("emails", [])),
            json.dumps(info.get("mx_records", [])),
            info.get("mx_count", 0),
            json.dumps(info.get("ip", [])),
            info.get("ttl"),
            json.dumps(info.get("ns_records", [])),
            info.get("ns_count", 0),
            int(bool(info.get("filtered", False))),
            json.dumps(info.get("reasons", [])),
            info.get("score", 0),
            int(bool(info.get("whitelisted", False))),
            int(bool(info.get("is_legit_subdomain", False))),
            info.get("cached_at", datetime.now().isoformat()),
            info.get("error")
        ))
        conn.commit()
        conn.close()
        logging.debug(f"Caché actualizado para {info.get('base_domain')}")
    except Exception as e:
        logging.error(f"Error al guardar en caché para {info.get('base_domain')}: {e}")


def save_result(result):
    """Guarda un resultado del pipeline en la base de datos SQLite (usa normalized_url para unicidad)."""
    try:
        conn = sqlite3.connect(DB_RESULTS)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR IGNORE INTO phishing_results (
                keyword, url, normalized_url, base_domain, title, snippet, suspicious, reasons, score,
                whitelisted, is_legit_subdomain, registrar, creation_date, expiration_date,
                country, emails, mx_records, mx_count, ip, ttl, ns_records, ns_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            result.get("keyword"),
            result.get("url"),
            result.get("normalized_url"),
            result.get("base_domain"),
            result.get("title"),
            result.get("snippet"),
            int(bool(result.get("suspicious"))),
            result.get("reasons"),
            result.get("score"),
            int(bool(result.get("whitelisted"))),
            int(bool(result.get("is_legit_subdomain"))),
            result.get("registrar"),
            result.get("creation_date"),
            result.get("expiration_date"),
            result.get("country"),
            json.dumps(result.get("emails", [])),
            json.dumps(result.get("mx_records", [])),
            result.get("mx_count", 0),
            json.dumps(result.get("ip", [])),
            result.get("ttl"),
            json.dumps(result.get("ns_records", [])),
            result.get("ns_count", 0)
        ))
        conn.commit()
        conn.close()
        logging.debug(f"Resultado guardado para {result.get('normalized_url')}")
    except Exception as e:
        logging.error(f"Error al guardar resultado para {result.get('normalized_url')}: {e}")


def get_suspicious_results(min_score=50):
    """Consulta resultados sospechosos desde la base de datos SQLite."""
    try:
        conn = sqlite3.connect(DB_RESULTS)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM phishing_results WHERE suspicious = 1 AND score >= ?
        """, (min_score,))
        rows = cursor.fetchall()
        conn.close()
        results = []
        for row in rows:
            results.append({
                "id": row[0],
                "keyword": row[1],
                "url": row[2],
                "normalized_url": row[3],
                "base_domain": row[4],
                "title": row[5],
                "snippet": row[6],
                "suspicious": bool(row[7]),
                "reasons": row[8],
                "score": row[9],
                "whitelisted": bool(row[10]),
                "is_legit_subdomain": bool(row[11]),
                "registrar": row[12],
                "creation_date": row[13],
                "expiration_date": row[14],
                "country": row[15],
                "emails": json.loads(row[16]) if row[16] else [],
                "mx_records": json.loads(row[17]) if row[17] else [],
                "mx_count": row[18],
                "ip": json.loads(row[19]) if row[19] else [],
                "ttl": row[20],
                "ns_records": json.loads(row[21]) if row[21] else [],
                "ns_count": row[22]
            })
        logging.info(f"Consultados {len(results)} resultados sospechosos con score >= {min_score}")
        return results
    except Exception as e:
        logging.error(f"Error al consultar resultados sospechosos: {e}")
        return []


def get_processed_urls():
    """Recupera todas las normalized_urls procesadas desde phishing_results.db."""
    try:
        conn = sqlite3.connect(DB_RESULTS)
        cursor = conn.cursor()
        cursor.execute("SELECT normalized_url, base_domain FROM phishing_results")
        rows = cursor.fetchall()
        conn.close()
        processed = {row[0]: row[1] for row in rows if row[0]}
        logging.info(f"Recuperadas {len(processed)} URLs procesadas")
        return processed
    except Exception as e:
        logging.error(f"Error al recuperar URLs procesadas: {e}")
        return {}
