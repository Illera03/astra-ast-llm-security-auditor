import hashlib
import sqlite3

from app.llm.client import LLMResponse


class AnalysisCache:
    """
    Cryptographic cache using SHA-256 and SQLite.
    Prevents sending redundant code snippets to the LLM to save time and compute.
    """

    def __init__(self, db_path: str = ".astra_cache.db") -> None:
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        """Creates the internal SQLite table if it doesn't exist."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS results (
                    hash_key TEXT PRIMARY KEY,
                    is_exploitable BOOLEAN,
                    confidence REAL,
                    exploit_path TEXT
                )
                """
            )
            conn.commit()

    def _generate_hash(self, text: str) -> str:
        """Generates a mathematically unique SHA-256 fingerprint for the text."""
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def get(self, context_text: str) -> LLMResponse | None:
        """Retrieves a cached LLM response if the exact context was already analyzed."""
        hash_key = self._generate_hash(context_text)

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT is_exploitable, confidence, exploit_path FROM results "
                "WHERE hash_key = ?",
                (hash_key,),
            )
            row = cursor.fetchone()

            if row:
                return LLMResponse(
                    is_exploitable=bool(row[0]),
                    confidence=float(row[1]),
                    exploit_path=str(row[2]),
                )
        return None

    def set(self, context_text: str, response: LLMResponse) -> None:
        """Saves an LLM response to the database linked to its SHA-256 hash."""
        hash_key = self._generate_hash(context_text)

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO results 
                (hash_key, is_exploitable, confidence, exploit_path)
                VALUES (?, ?, ?, ?)
                """,
                (
                    hash_key,
                    response.is_exploitable,
                    response.confidence,
                    response.exploit_path,
                ),
            )
            conn.commit()
