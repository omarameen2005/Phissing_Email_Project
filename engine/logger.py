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
        email_text TEXT,
        label TEXT NOT NULL,
        confidence REAL,
        reason TEXT,
        ip_address TEXT DEFAULT 'unknown',
        user_agent TEXT DEFAULT 'unknown',
        shap_data TEXT DEFAULT NULL     -- Added here
    );

    CREATE INDEX IF NOT EXISTS idx_timestamp ON email_logs(timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_label ON email_logs(label);
    """

    with get_conn() as conn:
        conn.executescript(create_table_sql)
        
        try:
            conn.execute("ALTER TABLE email_logs ADD COLUMN shap_data TEXT DEFAULT NULL")
            print("✓ shap_data column added successfully!")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e).lower():
                print("→ shap_data column already exists (good!)")
            else:
                raise e
                
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





# def backfill_all_shap():
#     import json
#     from model.shap_explain import get_shap_data
#     conn = get_conn()
    
#     logs = conn.execute("SELECT id, email_text FROM email_logs WHERE reason LIKE '%ML Model%'").fetchall()

#     print(f"Found {len(logs)} old ML logs. Backfilling now...")

#     success = 0
#     for log in logs:
#         if not log['email_text'] or len(log['email_text']) < 50:
#             continue
#         try:
#             shap_json = get_shap_data(log['email_text'])
#             conn.execute(
#                 "UPDATE email_logs SET shap_data = ? WHERE id = ?",
#                 (json.dumps(shap_json), log['id'])
#             )
#             success += 1
#             if success % 10 == 0:
#                 print(f"✓ {success} logs updated...")
#         except:
#             pass 

#     conn.commit()
#     print(f"\nBackfill finished! {success} old logs now have full 5-model graphs.")


init_db()  