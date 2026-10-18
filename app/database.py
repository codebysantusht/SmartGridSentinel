
import sqlite3
from pathlib import Path
from contextlib import contextmanager

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "smartgrid_sentinel.db"


def connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    with connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS meters (
            meter_id TEXT PRIMARY KEY,
            label TEXT NOT NULL,
            secret_hex TEXT NOT NULL,
            created_at TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'ACTIVE'
        );

        CREATE TABLE IF NOT EXISTS readings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            meter_id TEXT NOT NULL,
            sequence_no INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            consumption_wh INTEGER NOT NULL,
            encrypted_consumption TEXT,
            mac TEXT NOT NULL,
            chain_hash TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            FOREIGN KEY(meter_id) REFERENCES meters(meter_id),
            UNIQUE(meter_id, sequence_no)
        );

        CREATE TABLE IF NOT EXISTS baselines (
            meter_id TEXT PRIMARY KEY,
            root_hash TEXT NOT NULL,
            reading_count INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(meter_id) REFERENCES meters(meter_id)
        );

        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            meter_id TEXT,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL
        );
        """)

        # Migrate existing databases without deleting old readings.
        columns = {
            row["name"]
            for row in db.execute(
                "PRAGMA table_info(readings)"
            ).fetchall()
        }

        if "encrypted_consumption" not in columns:
            db.execute(
                "ALTER TABLE readings ADD COLUMN encrypted_consumption TEXT"
            )

        db.commit()


@contextmanager
def db_session():
    db = connect()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
