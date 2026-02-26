import sqlite3
import os
from datetime import datetime

# Define DB Path relative to this file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'data', 'bugscope.db')

def get_connection():
    """Get a connection to the SQLite database."""
    if not os.path.exists(os.path.dirname(DB_PATH)):
        os.makedirs(os.path.dirname(DB_PATH))
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize the database tables."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("PRAGMA foreign_keys = ON;")
    
    # 1. Sessions Table
    cursor.execute('''CREATE TABLE IF NOT EXISTS sessions 
                      (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                       start_time TEXT, 
                       target_host TEXT)''')
    
    # 2. Traffic Table
    cursor.execute('''CREATE TABLE IF NOT EXISTS traffic 
                      (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                       session_id INTEGER, 
                       method TEXT, 
                       host TEXT, 
                       path TEXT, 
                       timestamp TEXT,
                       FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE)''')
    
    # 3. Vulnerabilities Table
    cursor.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities 
                      (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                       traffic_id INTEGER, 
                       severity TEXT, 
                       description TEXT, 
                       test_case TEXT,
                       FOREIGN KEY (traffic_id) REFERENCES traffic(id) ON DELETE CASCADE)''')
    
    conn.commit()
    conn.close()
    print(f"✅ Database initialized at: {DB_PATH}")

def create_session(target_host="Unknown"):
    """Create a new session and return the ID."""
    conn = get_connection()
    cursor = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("INSERT INTO sessions (start_time, target_host) VALUES (?, ?)", 
                   (timestamp, target_host))
    conn.commit()
    session_id = cursor.lastrowid
    conn.close()
    return session_id

def log_traffic(session_id, method, host, path):
    """Log a request and return the Traffic ID."""
    conn = get_connection()
    cursor = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("INSERT INTO traffic (session_id, method, host, path, timestamp) VALUES (?, ?, ?, ?, ?)",
                   (session_id, method, host, path, timestamp))
    conn.commit()
    traffic_id = cursor.lastrowid
    conn.close()
    return traffic_id

def log_vulnerability(traffic_id, severity, description, test_case):
    """Log a vulnerability linked to specific traffic."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO vulnerabilities (traffic_id, severity, description, test_case) VALUES (?, ?, ?, ?)",
                   (traffic_id, severity, description, test_case))
    conn.commit()
    conn.close()