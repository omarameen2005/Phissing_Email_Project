import sqlite3
import os
from datetime import datetime
from typing import List, Dict, Any, Optional


DB_DIR = "data"
DB_PATH = os.path.join(DB_DIR, "database.db")
os.makedirs(DB_DIR, exist_ok=True)



def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # Better concurrency
    conn.execute("PRAGMA foreign_keys=ON")
    return conn



def init_db() -> None:

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


def log_scan(
    email_text: str,
    label: str,
    confidence: Optional[float] = None,
    reason: str = "",
    ip_address: str = "unknown",
    user_agent: str = "unknown"
) -> int:

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

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


def get_recent_logs(limit: int = 50) -> List[Dict[str, Any]]:

    limit = min(max(limit, 1), 1000) 

    with get_conn() as conn:
        cursor = conn.execute(
            "SELECT * FROM email_logs ORDER BY id DESC LIMIT ?",
            (limit,)
        )
        logs = [dict(row) for row in cursor.fetchall()]
    return logs


def get_stats() -> Dict[str, int]:

    with get_conn() as conn:
        cursor = conn.execute("""
            SELECT label, COUNT(*) as count
            FROM email_logs
            GROUP BY label
        """)
        rows = cursor.fetchall()

  
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
                stats["Safe"] += count 
            total += count

        stats["total"] = total
        return stats


def clear_logs() -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM email_logs")
        conn.execute("VACUUM")
        conn.commit()
    print("All logs cleared.")


init_db()  