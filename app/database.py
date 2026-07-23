import json
import sqlite3
from pathlib import Path


DATABASE_PATH = Path("data/investigations.db")


def get_connection():
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS investigations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subject TEXT NOT NULL,
                sender TEXT NOT NULL,
                verdict TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                email_hash TEXT NOT NULL UNIQUE,
                results TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )


def save_investigation(result: dict) -> int:
    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO investigations (
                subject,
                sender,
                verdict,
                risk_score,
                email_hash,
                results
            )
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(email_hash) DO UPDATE SET
                subject = excluded.subject,
                sender = excluded.sender,
                verdict = excluded.verdict,
                risk_score = excluded.risk_score,
                results = excluded.results
            """,
            (
                result["subject"],
                result["sender"],
                result["verdict"],
                result["risk_score"],
                result["email_hash"],
                json.dumps(result),
            ),
        )

        if cursor.lastrowid:
            return cursor.lastrowid

        existing = connection.execute(
            "SELECT id FROM investigations WHERE email_hash = ?",
            (result["email_hash"],),
        ).fetchone()

        return existing["id"]


def get_investigations(limit: int = 100) -> list[dict]:
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT id, subject, sender, verdict, risk_score, created_at
            FROM investigations
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [dict(row) for row in rows]


def get_investigation(investigation_id: int) -> dict | None:
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM investigations WHERE id = ?",
            (investigation_id,),
        ).fetchone()

    if row is None:
        return None

    result = json.loads(row["results"])
    result["id"] = row["id"]
    result["created_at"] = row["created_at"]
    return result


def get_statistics() -> dict:
    with get_connection() as connection:
        total = connection.execute(
            "SELECT COUNT(*) FROM investigations"
        ).fetchone()[0]

        rows = connection.execute(
            """
            SELECT verdict, COUNT(*) AS count
            FROM investigations
            GROUP BY verdict
            """
        ).fetchall()

    verdict_counts = {row["verdict"]: row["count"] for row in rows}

    return {
        "total": total,
        "malicious": verdict_counts.get("Malicious", 0),
        "suspicious": verdict_counts.get("Suspicious", 0),
        "likely_safe": verdict_counts.get("Likely Safe", 0),
    }
