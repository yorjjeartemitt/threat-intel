import sqlite3
def init_db():
    conn=sqlite3.connect("threats.db")
    cursor=conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            abuse_score INTEGER,
            country TEXT,
            checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()
def save_reports(ip,scores,country):
    conn=sqlite3.connect("threats.db")
    cursor=conn.cursor()
    cursor.execute("INSERT INTO reports (ip,abuse_score,country) VALUES (?,?, ?)",(ip,scores,country))  
    conn.commit()
    conn.close()