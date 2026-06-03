import sqlite3, datetime

DB = "data.db"

def init_db():
    conn = sqlite3.connect(DB)
    c    = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            upi        TEXT,
            score      INTEGER,
            verdict    TEXT,
            reason     TEXT,
            checked_at TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS url_scans (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            url        TEXT,
            verdict    TEXT,
            malicious  INTEGER,
            suspicious INTEGER,
            total      INTEGER,
            tip        TEXT,
            scanned_at TEXT
        )
    ''')
    conn.commit()
    conn.close()

def save_report(upi, score, verdict, reason):
    conn = sqlite3.connect(DB)
    c    = conn.cursor()
    c.execute(
        "INSERT INTO reports (upi, score, verdict, reason, checked_at) VALUES (?,?,?,?,?)",
        (upi, score, verdict, reason, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()
    conn.close()

def save_url_scan(url, verdict, malicious, suspicious, total, tip):
    conn = sqlite3.connect(DB)
    c    = conn.cursor()
    c.execute(
        "INSERT INTO url_scans (url, verdict, malicious, suspicious, total, tip, scanned_at) VALUES (?,?,?,?,?,?,?)",
        (url, verdict, malicious, suspicious, total, tip,
         datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()
    conn.close()

def get_all_reports():
    conn = sqlite3.connect(DB)
    c    = conn.cursor()
    c.execute("SELECT * FROM reports ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    return rows

def get_all_url_scans():
    conn = sqlite3.connect(DB)
    c    = conn.cursor()
    c.execute("SELECT * FROM url_scans ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    return rows

def clear_all_reports():
    conn = sqlite3.connect(DB)
    c    = conn.cursor()
    c.execute("DELETE FROM reports")
    c.execute("DELETE FROM url_scans")
    for tbl in ("reports", "url_scans"):
        c.execute("DELETE FROM sqlite_sequence WHERE name=?", (tbl,))
    conn.commit()
    conn.close()
