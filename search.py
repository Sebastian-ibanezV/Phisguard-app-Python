"""
database.py - Gestión de bases de datos para resultados y caché WHOIS
Integrado con search.py y whois_lookup.py
"""

import sqlite3
import json
import logging
from datetime import datetime
import csv
from typing import Any, Dict, Optional, List

logger = logging.getLogger(__name__)

# Rutas de las bases de datos
DB_RESULTS = "phishing_results.db"
DB_CACHE = "whois_cache.db"

# =============================
# Inicialización de las bases
# =============================

def init_db():
    """Inicializa ambas bases de datos."""
    _init_results_db()
    _init_cache_db()


def _connect(db_path: str):
    """Crea conexión SQLite con buenas configuraciones de rendimiento."""
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def _init_results_db():
    with _connect(DB_RESULTS) as conn:
        cursor = conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS phishing_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            normalized_url TEXT UNIQUE,
            domain TEXT,
            keyword TEXT,
            title TEXT,
            snippet TEXT,
            reasons TEXT,
            score INTEGER,
            suspicious INTEGER DEFAULT 0,
            filtered INTEGER DEFAULT 0,
            whitelisted INTEGER DEFAULT 0,
            registrar TEXT,
            creation_date TEXT,
            expiration_date TEXT,
            ns_records TEXT,
            mx_records TEXT,
            last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_normalized_url ON phishing_results(normalized_url)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_keyword ON phishing_results(keyword)")
        conn.commit()


def _init_cache_db():
    with _connect(DB_CACHE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS whois_cache (
            domain TEXT PRIMARY KEY,
            data TEXT,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        conn.commit()

# =============================
# Utilidades internas
# =============================

def _normalize_date(date_value: Any) -> Optional[str]:
    """Convierte fecha WHOIS a string ISO. Acepta datetime, str o None."""
    if not date_value:
        return None
    if isinstance(date_value, datetime):
        return date_value.strftime("%Y-%m-%dT%H:%M:%S")
    if isinstance(date_value, str):
        try:
            dt = datetime.fromisoformat(date_value.replace("Z", ""))
            return dt.strftime("%Y-%m-%dT%H:%M:%S")
        except Exception:
            return date_value
    return str(date_value)


def _safe_load_reasons(reasons: Any) -> list:
    """Convierte campo reasons a lista de strings válida."""
    if not reasons:
        return []
    if isinstance(reasons, list):
        return [str(r) for r in reasons if r]
    if isinstance(reasons, str):
        try:
            parsed = json.loads(reasons)
            if isinstance(parsed, list):
                return [str(r) for r in parsed if r]
        except Exception:
            return [reasons]
    return [str(reasons)]

# =============================
# Funciones principales
# =============================

def save_result(result: Dict[str, Any]):
    """Guarda o actualiza un resultado en phishing_results."""
    if not result.get("keyword") or not result.get("normalized_url"):
        logger.warning("Resultado incompleto descartado: %s", result)
        return

    score = result.get("score") or 0
    try:
        score = max(0, int(score))
    except Exception:
        score = 0

    with _connect(DB_RESULTS) as conn:
        cursor = conn.cursor()
        cursor.execute("""
        INSERT INTO phishing_results (
            url, normalized_url, domain, keyword, title, snippet,
            reasons, score, suspicious, filtered, whitelisted,
            registrar, creation_date, expiration_date,
            ns_records, mx_records, last_checked
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(normalized_url) DO UPDATE SET
            url=excluded.url,
            domain=excluded.domain,
            keyword=excluded.keyword,
            title=excluded.title,
            snippet=excluded.snippet,
            reasons=excluded.reasons,
            score=excluded.score,
            suspicious=excluded.suspicious,
            filtered=excluded.filtered,
            whitelisted=excluded.whitelisted,
            registrar=excluded.registrar,
            creation_date=excluded.creation_date,
            expiration_date=excluded.expiration_date,
            ns_records=excluded.ns_records,
            mx_records=excluded.mx_records,
            last_checked=CURRENT_TIMESTAMP
        """, (
            result.get("url"),
            result.get("normalized_url"),
            result.get("domain"),
            result.get("keyword"),
            result.get("title"),
            result.get("snippet"),
            json.dumps(_safe_load_reasons(result.get("reasons"))),
            score,
            int(result.get("suspicious", 0)),
            int(result.get("filtered", 0)),
            int(result.get("whitelisted", 0)),
            result.get("registrar"),
            _normalize_date(result.get("creation_date")),
            _normalize_date(result.get("expiration_date")),
            json.dumps(result.get("ns_records") or []),
            json.dumps(result.get("mx_records") or []),
        ))
        conn.commit()
        logger.info("Guardado resultado para dominio %s", result.get("domain"))

def save_domain_info(domain: str, info: Dict[str, Any]):
    """Guarda información WHOIS en caché."""
    with _connect(DB_CACHE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
        INSERT INTO whois_cache (domain, data, last_updated)
        VALUES (?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(domain) DO UPDATE SET
            data=excluded.data,
            last_updated=CURRENT_TIMESTAMP
        """, (domain, json.dumps(info)))
        conn.commit()


def get_cached_domain_info(domain: str, max_age_days: int = 7) -> Optional[Dict[str, Any]]:
    """Recupera datos WHOIS de caché si no están caducados."""
    with _connect(DB_CACHE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT data, last_updated FROM whois_cache WHERE domain = ?", (domain,))
        row = cursor.fetchone()
        if not row:
            return None
        data, last_updated = row
        try:
            last_dt = datetime.fromisoformat(last_updated)
            if (datetime.now() - last_dt).days > max_age_days:
                return None
        except Exception:
            return None
        try:
            return json.loads(data)
        except Exception:
            return None


def get_processed_urls() -> Dict[str, str]:
    """
    Devuelve un dict {normalized_url: keyword} de URLs ya procesadas en la DB.
    """
    with _connect(DB_RESULTS) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT normalized_url, keyword FROM phishing_results")
        rows = cursor.fetchall()
    return {row[0]: row[1] for row in rows}


def get_suspicious_results(min_score: int = 50) -> List[Dict[str, Any]]:
    """
    Devuelve todos los resultados sospechosos con score >= min_score.
    """
    with _connect(DB_RESULTS) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
        SELECT * FROM phishing_results
        WHERE suspicious = 1 AND score >= ?
        ORDER BY score DESC
        """, (min_score,))
        rows = cursor.fetchall()
    return [dict(row) for row in rows]


def export_results_to_csv(filepath: str = "results.csv"):
    """Exporta todos los resultados a un archivo CSV."""
    with _connect(DB_RESULTS) as conn:
        cursor = conn.cursor()
        rows = cursor.execute("SELECT * FROM phishing_results").fetchall()
        headers = [desc[0] for desc in cursor.description]

    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)

    logger.info("Exportados %d resultados a %s", len(rows), filepath)


# =============================
# Inicialización al importar
# =============================

init_db()
