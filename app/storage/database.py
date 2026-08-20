import aiosqlite
import logging
from pathlib import Path
from typing import AsyncGenerator
from app.config import settings

logger = logging.getLogger("argus.storage.database")

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    client_id TEXT NOT NULL,
    model TEXT NOT NULL,
    action TEXT NOT NULL,          -- ALLOW | BLOCKED | REDACTED | FLAGGED
    risk_score REAL NOT NULL,
    latency_ms REAL NOT NULL,
    prompt_tokens INTEGER DEFAULT 0,
    completion_tokens INTEGER DEFAULT 0,
    request_prompt TEXT,
    sanitized_prompt TEXT,
    raw_response TEXT,
    sanitized_response TEXT,
    violations_json TEXT,         -- JSON array of triggered inspector rules
    inspector_details_json TEXT,  -- JSON dict of all inspector scores & metrics
    client_ip TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_risk_score ON audit_logs(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_audit_client_id ON audit_logs(client_id);
"""


class DatabaseManager:
    def __init__(self, db_path: Path):
        self.db_path = db_path

    async def init_db(self) -> None:
        """Initialize database schema and set WAL pragma for high concurrency."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("PRAGMA journal_mode=WAL;")
            await db.execute("PRAGMA synchronous=NORMAL;")
            await db.executescript(SCHEMA_SQL)
            await db.commit()
        logger.info(f"Database initialized successfully at {self.db_path}")

    def get_connection(self):
        """Returns an async context manager for SQLite connection."""
        return aiosqlite.connect(self.db_path)


db_manager = DatabaseManager(settings.db_full_path)


async def get_db_session() -> AsyncGenerator[aiosqlite.Connection, None]:
    async with db_manager.get_connection() as db:
        db.row_factory = aiosqlite.Row
        yield db
