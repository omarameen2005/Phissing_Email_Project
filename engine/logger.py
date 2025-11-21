# engine/logger.py
"""
Persistent Logging System using SQLite
Stores every scan with full context for dashboard, analytics, and forensics.
Thread-safe, efficient, and auto-initialized.
"""
import sqlite3
import os
from datetime import datetime
from typing import List, Dict, Any, Optional

# ------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------
DB_DIR = "data"
DB_PATH = os.path.join(DB_DIR, "database.db")
os.makedirs(DB_DIR, exist_ok=True)


# ------------------------------------------------------------------
# Database Connection (Thread-safe)
# ------------------------------------------------------------------
def get_conn() -> sqlite3.Connection:
    """Return a thread-local SQLite connection with row factory."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # Better concurrency
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


# ------------------------------------------------------------------
# Initialize Database Schema
# ------------------------------------------------------------------
def init_db() -> None:
    """Create the email_logs table if it doesn't exist."""
    create_table_sql = """
    CREATE TABLE IF NOT EXISTS email_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        email_text TEXT,           -- Truncated for performance
        label TEXT NOT NULL,
        confidence REAL,           -- 0.0 to 1.0 or NULL
        reason TEXT,
        ip_address TEXT DEFAULT 'unknown',
        user_agent TEXT DEFAULT 'unknown'
    );

    CREATE INDEX IF NOT EXISTS idx_timestamp ON email_logs(timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_label ON email_logs(label);
    """

    with get_conn() as conn:
        conn.executescript(create_table_sql)
        conn.commit()


# ------------------------------------------------------------------
# Log a Scan Result
# ------------------------------------------------------------------
def log_scan(
    email_text: str,
    label: str,
    confidence: Optional[float] = None,
    reason: str = "",
    ip_address: str = "unknown",
    user_agent: str = "unknown"
) -> int:
    """
    Log a completed email scan.
    Returns the inserted row ID.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Truncate email to prevent DB bloat (first 1500 chars is enough for analysis)
    truncated_email = email_text[:1500] + ("..." if len(email_text) > 1500 else "")

    insert_sql = """
    INSERT INTO email_logs
        (timestamp, email_text, label, confidence, reason, ip_address, user_agent)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """

    with get_conn() as conn:
        cursor = conn.execute(insert_sql, (
            timestamp,
            truncated_email,
            label,
            confidence,
            reason or "",
            ip_address,
            user_agent
        ))
        conn.commit()
        return cursor.lastrowid


# ------------------------------------------------------------------
# Retrieve Recent Logs
# ------------------------------------------------------------------
def get_recent_logs(limit: int = 50) -> List[Dict[str, Any]]:
    """Get the most recent scan logs (newest first)."""
    limit = min(max(limit, 1), 1000)  # Clamp between 1 and 1000

    with get_conn() as conn:
        cursor = conn.execute(
            "SELECT * FROM email_logs ORDER BY id DESC LIMIT ?",
            (limit,)
        )
        logs = [dict(row) for row in cursor.fetchall()]
    return logs


# ------------------------------------------------------------------
# Dashboard Statistics
# ------------------------------------------------------------------
def get_stats() -> Dict[str, int]:
    """Return aggregated statistics for the dashboard."""
    with get_conn() as conn:
        cursor = conn.execute("""
            SELECT label, COUNT(*) as count
            FROM email_logs
            GROUP BY label
        """)
        rows = cursor.fetchall()

        # Initialize all counters
        stats = {
            "total": 0,
            "Phishing": 0,
            "Safe": 0,
            "Suspicious": 0,
            "Error": 0
        }

        total = 0
        for row in rows:
            label = row["label"]
            count = row["count"]
            if label in stats:
                stats[label] = count
            else:
                stats["Safe"] += count  # Fallback unknown labels to Safe
            total += count

        stats["total"] = total
        return stats


# ------------------------------------------------------------------
# Optional: Clear Logs (for testing)
# ------------------------------------------------------------------
def clear_logs() -> None:
    """Delete all logs — useful for development."""
    with get_conn() as conn:
        conn.execute("DELETE FROM email_logs")
        conn.execute("VACUUM")
        conn.commit()
    print("All logs cleared.")


# ------------------------------------------------------------------
# Auto-initialize on import
# ------------------------------------------------------------------
init_db()  # Safe to call multiple times