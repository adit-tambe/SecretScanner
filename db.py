"""
SecretScanner Engine - Database Operations (db.py)

WHAT THIS FILE DOES:
When `scanner.py` finds a secret and `validators.py` confirms it, we need somewhere 
permanent to store it so the user can view it on the dashboard later. 
This file talks to an SQLite database (which is basically a database stored in a single file 
called `analytics.db`).

HOW IT WORKS (For Beginners):
1. **init_db**: This runs when the server starts. If the database file doesn't exist, 
   it creates it and sets up two tables (think of them like Excel spreadsheets).
   - `scans` table: Records the history of every scan (when it happened, how long it took).
   - `findings` table: Records every individual leaked secret found during those scans.
2. **record_scan**: Saves a row to the `scans` table.
3. **record_finding**: Saves a row to the `findings` table.
"""

import sqlite3
import os
import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "analytics.db")

def init_db():
    """
    Creates the database tables if they don't already exist.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            timestamp DATETIME,
            mode TEXT,
            target_type TEXT,
            target TEXT,
            repos_scanned INTEGER,
            files_scanned INTEGER,
            time_taken REAL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT,
            repository TEXT,
            file TEXT,
            line TEXT,
            secret_type TEXT,
            token_preview TEXT,
            severity TEXT,
            is_active TEXT,
            metadata TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )
    ''')
    conn.commit()
    conn.close()

def record_scan(scan_id, mode, target_type, target, repos_scanned, files_scanned, time_taken):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO scans (id, timestamp, mode, target_type, target, repos_scanned, files_scanned, time_taken)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (scan_id, datetime.datetime.utcnow(), mode, target_type, target, repos_scanned, files_scanned, time_taken))
    conn.commit()
    conn.close()

def record_finding(scan_id, repository, file_path, line, secret_type, token_preview, severity, is_active, metadata):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO findings (scan_id, repository, file, line, secret_type, token_preview, severity, is_active, metadata)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (scan_id, repository, file_path, str(line), secret_type, token_preview, severity, is_active, metadata))
    conn.commit()
    conn.close()

def get_analytics_summary():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM findings")
    total_secrets = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM findings WHERE is_active = 'active'")
    active_leaks = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM scans")
    total_scans = cursor.fetchone()[0]
    
    # Calculate average time to identify a breach (just a fun metric using average scan time for the demo)
    cursor.execute("SELECT AVG(time_taken) FROM scans")
    avg_time = cursor.fetchone()[0] or 0.0
    
    # Get top secret types
    cursor.execute("SELECT secret_type, COUNT(*) as cnt FROM findings GROUP BY secret_type ORDER BY cnt DESC LIMIT 5")
    top_types = cursor.fetchall()
    
    conn.close()
    
    return {
        "total_secrets": total_secrets,
        "active_leaks": active_leaks,
        "preventable_leaks": total_secrets - active_leaks,
        "total_scans": total_scans,
        "avg_scan_time_sec": round(avg_time, 2),
        "top_types": [{"type": row[0], "count": row[1]} for row in top_types]
    }

def record_scan_and_findings(scan_id, mode, target_type, target, repos_scanned, files_scanned, time_taken, findings):
    conn = sqlite3.connect(DB_PATH)
    conn.execute('PRAGMA journal_mode=WAL')
    try:
        conn.execute('''
            INSERT INTO scans (id, timestamp, mode, target_type, target, repos_scanned, files_scanned, time_taken)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (scan_id, datetime.datetime.utcnow(), mode, target_type, target, repos_scanned, files_scanned, time_taken))
        
        conn.executemany('''
            INSERT INTO findings (scan_id, repository, file, line, secret_type, token_preview, severity, is_active, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', [
            (
                scan_id, 
                f["occurrences"][0]["repository"] if f["occurrences"] else "",
                f["occurrences"][0]["file"] if f["occurrences"] else "",
                f["occurrences"][0]["line"] if f["occurrences"] else "",
                f["type"], 
                f["preview"], 
                f["severity"], 
                f.get("is_active", "unknown"), 
                f.get("metadata", "")
            ) for f in findings
        ])
        conn.commit()
    finally:
        conn.close()
