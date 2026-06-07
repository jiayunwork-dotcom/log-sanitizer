import os
import sqlite3
import threading
from typing import Optional, Dict, Callable
from .utils import hmac_sha256


DEFAULT_HMAC_KEY = b"log-sanitizer-default-key-please-change"


class MappingManager:
    def __init__(
        self,
        db_path: Optional[str] = None,
        hmac_key: Optional[bytes] = None,
        in_memory: bool = False
    ):
        self.in_memory = in_memory or db_path is None
        self.db_path = db_path
        self.hmac_key = hmac_key or DEFAULT_HMAC_KEY
        self._lock = threading.Lock()
        self._memory_cache: Dict[str, str] = {}
        self._conn: Optional[sqlite3.Connection] = None
        
        if not self.in_memory:
            self._init_database()

    def _init_database(self) -> None:
        if self.db_path is None:
            return
        db_dir = os.path.dirname(os.path.abspath(self.db_path))
        os.makedirs(db_dir, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        cursor = self._conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sanitization_mappings (
                hmac_key TEXT PRIMARY KEY,
                sanitized_value TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        self._conn.commit()

    def _get_hmac(self, original_value: str) -> str:
        return hmac_sha256(original_value, self.hmac_key)

    def get(self, original_value: str, generator: Callable[[], str]) -> str:
        hmac_key = self._get_hmac(original_value)
        
        with self._lock:
            if hmac_key in self._memory_cache:
                return self._memory_cache[hmac_key]
            
            if not self.in_memory and self._conn:
                cursor = self._conn.cursor()
                cursor.execute(
                    'SELECT sanitized_value FROM sanitization_mappings WHERE hmac_key = ?',
                    (hmac_key,)
                )
                result = cursor.fetchone()
                if result:
                    self._memory_cache[hmac_key] = result[0]
                    return result[0]
            
            sanitized_value = generator()
            self._memory_cache[hmac_key] = sanitized_value
            
            if not self.in_memory and self._conn:
                cursor = self._conn.cursor()
                cursor.execute(
                    'INSERT OR IGNORE INTO sanitization_mappings (hmac_key, sanitized_value) VALUES (?, ?)',
                    (hmac_key, sanitized_value)
                )
                self._conn.commit()
            
            return sanitized_value

    def bulk_get(self, values: Dict[str, Callable[[], str]]) -> Dict[str, str]:
        results = {}
        for original_value, generator in values.items():
            results[original_value] = self.get(original_value, generator)
        return results

    def clear_cache(self) -> None:
        with self._lock:
            self._memory_cache.clear()

    def close(self) -> None:
        with self._lock:
            if self._conn:
                self._conn.close()
                self._conn = None

    def __enter__(self) -> 'MappingManager':
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
