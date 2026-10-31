"""
Database module for Fake Website Detector Using Web Security Analysis.
Provides SQLite database connection management, schema initialization, and parameterized CRUD operations.
"""

import sqlite3
import json
import os
from datetime import datetime
from typing import List, Dict, Any, Optional
import config


def get_connection(db_path: str = None) -> sqlite3.Connection:
    """Creates a database connection with dictionary-like row access."""
    path = db_path or config.DATABASE_PATH
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str = None) -> None:
    """Initializes the SQLite database tables and indexes if they do not exist."""
    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    submitted_url TEXT NOT NULL,
                    normalized_url TEXT NOT NULL,
                    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    risk_score INTEGER NOT NULL,
                    risk_category TEXT NOT NULL,
                    risk_tier TEXT NOT NULL,
                    findings_json TEXT NOT NULL,
                    scan_status TEXT NOT NULL,
                    resolved_ip TEXT,
                    http_status INTEGER
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_history_scanned_at ON scan_history(scanned_at DESC)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_history_risk_tier ON scan_history(risk_tier)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_history_url ON scan_history(normalized_url)")
    finally:
        conn.close()


def insert_scan(
    submitted_url: str,
    normalized_url: str,
    risk_score: int,
    risk_category: str,
    risk_tier: str,
    findings: Dict[str, Any],
    scan_status: str = "completed",
    resolved_ip: Optional[str] = None,
    http_status: Optional[int] = None,
    db_path: str = None
) -> int:
    """
    Inserts a completed website scan record into the database.
    Uses parameterized query to prevent SQL injection.
    Returns the newly inserted record ID.
    """
    conn = get_connection(db_path)
    findings_str = json.dumps(findings)
    now_iso = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        with conn:
            cursor = conn.execute(
                """
                INSERT INTO scan_history (
                    submitted_url, normalized_url, scanned_at,
                    risk_score, risk_category, risk_tier,
                    findings_json, scan_status, resolved_ip, http_status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    submitted_url,
                    normalized_url,
                    now_iso,
                    risk_score,
                    risk_category,
                    risk_tier,
                    findings_str,
                    scan_status,
                    resolved_ip,
                    http_status
                )
            )
            return cursor.lastrowid
    finally:
        conn.close()


def get_scan_by_id(scan_id: int, db_path: str = None) -> Optional[Dict[str, Any]]:
    """Retrieves a single scan record by primary key."""
    conn = get_connection(db_path)
    try:
        row = conn.execute("SELECT * FROM scan_history WHERE id = ?", (scan_id,)).fetchone()
        if not row:
            return None
        record = dict(row)
        try:
            record["findings"] = json.loads(record["findings_json"])
        except Exception:
            record["findings"] = {}
        return record
    finally:
        conn.close()


def get_recent_scans(limit: int = 5, db_path: str = None) -> List[Dict[str, Any]]:
    """Retrieves the most recent scans for the home page and dashboard preview."""
    conn = get_connection(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM scan_history ORDER BY scanned_at DESC, id DESC LIMIT ?",
            (limit,)
        ).fetchall()
        results = []
        for r in rows:
            rec = dict(r)
            try:
                rec["findings"] = json.loads(rec["findings_json"])
            except Exception:
                rec["findings"] = {}
            results.append(rec)
        return results
    finally:
        conn.close()


def get_all_scans(
    search: Optional[str] = None,
    category: Optional[str] = None,
    sort_order: str = "desc",
    db_path: str = None
) -> List[Dict[str, Any]]:
    """
    Retrieves filtered and searched scans for the History page.
    Uses parameterized query for all dynamic filter variables.
    """
    conn = get_connection(db_path)
    try:
        query = "SELECT * FROM scan_history WHERE 1=1"
        params: List[Any] = []

        if search and search.strip():
            query += " AND (submitted_url LIKE ? OR normalized_url LIKE ?)"
            term = f"%{search.strip()}%"
            params.extend([term, term])

        if category and category.lower() in ("low", "medium", "high"):
            query += " AND risk_tier = ?"
            params.append(category.lower())

        order_dir = "ASC" if sort_order.lower() == "asc" else "DESC"
        query += f" ORDER BY scanned_at {order_dir}, id {order_dir}"

        rows = conn.execute(query, params).fetchall()
        results = []
        for r in rows:
            rec = dict(r)
            try:
                rec["findings"] = json.loads(rec["findings_json"])
            except Exception:
                rec["findings"] = {}
            results.append(rec)
        return results
    finally:
        conn.close()


def get_dashboard_stats(db_path: str = None) -> Dict[str, Any]:
    """
    Calculates aggregated statistics directly from stored scan records.
    Never returns hardcoded placeholder numbers.
    """
    conn = get_connection(db_path)
    try:
        total_count = conn.execute("SELECT COUNT(*) AS count FROM scan_history").fetchone()["count"]
        low_count = conn.execute("SELECT COUNT(*) AS count FROM scan_history WHERE risk_tier = 'low'").fetchone()["count"]
        med_count = conn.execute("SELECT COUNT(*) AS count FROM scan_history WHERE risk_tier = 'medium'").fetchone()["count"]
        high_count = conn.execute("SELECT COUNT(*) AS count FROM scan_history WHERE risk_tier = 'high'").fetchone()["count"]
        
        avg_row = conn.execute("SELECT AVG(risk_score) AS avg_score FROM scan_history").fetchone()
        avg_score = round(avg_row["avg_score"] or 0, 1)

        recent = get_recent_scans(limit=6, db_path=db_path)

        return {
            "total_scans": total_count,
            "low_risk_count": low_count,
            "medium_risk_count": med_count,
            "high_risk_count": high_count,
            "avg_risk_score": avg_score,
            "recent_scans": recent
        }
    finally:
        conn.close()


def delete_scan(scan_id: int, db_path: str = None) -> bool:
    """Deletes an individual scan by ID. Returns True if row was deleted."""
    conn = get_connection(db_path)
    try:
        with conn:
            cursor = conn.execute("DELETE FROM scan_history WHERE id = ?", (scan_id,))
            return cursor.rowcount > 0
    finally:
        conn.close()


def clear_all_scans(db_path: str = None) -> bool:
    """Clears all scan history records. Returns True upon success."""
    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute("DELETE FROM scan_history")
            return True
    finally:
        conn.close()
