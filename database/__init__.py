"""
Database package for Fake Website Detector Using Web Security Analysis.
"""

from .db import (
    init_db,
    insert_scan,
    get_scan_by_id,
    get_recent_scans,
    get_all_scans,
    get_dashboard_stats,
    delete_scan,
    clear_all_scans,
)

__all__ = [
    "init_db",
    "insert_scan",
    "get_scan_by_id",
    "get_recent_scans",
    "get_all_scans",
    "get_dashboard_stats",
    "delete_scan",
    "clear_all_scans",
]
