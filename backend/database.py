import sqlite3
import json
from typing import List, Dict, Any

DB_FILE = "idshield.db"

def get_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row  # Returns rows as dictionary-like objects
    return conn

def init_db():
    """Creates the persistent document table if it doesn't already exist."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            id TEXT PRIMARY KEY,
            doc_type TEXT,
            subject_masked_id TEXT,
            risk_score INTEGER,
            status TEXT,
            tampering_detected INTEGER,
            qr_status TEXT,
            face_detected INTEGER,
            processing_time_seconds REAL,
            timestamp TEXT,
            raw_json TEXT
        )
    """)
    conn.commit()
    conn.close()

def save_document(doc: Dict[str, Any]):
    """Persists a screened document dossier into SQLite."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR REPLACE INTO documents (
            id, doc_type, subject_masked_id, risk_score, status,
            tampering_detected, qr_status, face_detected,
            processing_time_seconds, timestamp, raw_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        doc.get("id"),
        doc.get("docType"),
        doc.get("subjectMaskedId"),
        doc.get("riskScore"),
        doc.get("status"),
        1 if doc.get("tamperingDetected") else 0,
        doc.get("qrStatus"),
        1 if doc.get("faceDetected") else 0,
        doc.get("processingTimeSeconds", 0.0),
        doc.get("timestamp"),
        json.dumps(doc)
    ))
    conn.commit()
    conn.close()

def get_all_documents() -> List[Dict[str, Any]]:
    """Fetches all scanned records ordered from newest to oldest."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT raw_json FROM documents ORDER BY rowid DESC")
    rows = cursor.fetchall()
    conn.close()
    
    records = []
    for row in rows:
        try:
            records.append(json.loads(row["raw_json"]))
        except Exception:
            continue
    return records

def clear_documents():
    """Wipes all saved inspection records from SQLite."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM documents")
    conn.commit()
    conn.close()
