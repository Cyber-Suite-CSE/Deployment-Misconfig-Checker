#!/usr/bin/env python3
"""
SQLite database provider for job management
"""

import sqlite3
import json
import threading
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from contextlib import contextmanager


class DatabaseException(Exception):
    """Database-related exceptions"""

    pass


class Database:
    """
    Singleton SQLite database provider for job management.

    Provides CRUD operations for scan jobs with filtering,
    sorting, and pagination support.
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls, db_path: str = "backend/jobs.db"):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(Database, cls).__new__(cls)
                    cls._instance._db_path = db_path
                    cls._instance._conn = None
                    cls._instance._initialize()
        return cls._instance

    def _initialize(self):
        """Initialize database connection and create tables"""
        try:
            self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._create_tables()
            self._create_indexes()
        except sqlite3.Error as e:
            raise DatabaseException(f"Failed to initialize database: {e}")

    def _create_tables(self):
        """Create jobs table if it doesn't exist"""
        cursor = self._conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT UNIQUE NOT NULL,
                domain TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'completed', 'failed')),
                execution_history TEXT,
                created_at TEXT NOT NULL,
                scan_results TEXT,
                error TEXT
            )
        """)
        self._conn.commit()

    def _create_indexes(self):
        """Create indexes for performance"""
        cursor = self._conn.cursor()
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status)",
            "CREATE INDEX IF NOT EXISTS idx_jobs_created_at ON jobs(created_at)",
            "CREATE INDEX IF NOT EXISTS idx_jobs_domain ON jobs(domain)",
        ]
        for index in indexes:
            cursor.execute(index)
        self._conn.commit()

    @contextmanager
    def _cursor(self):
        """Context manager for cursor operations"""
        cursor = self._conn.cursor()
        try:
            yield cursor
            self._conn.commit()
        except sqlite3.Error as e:
            self._conn.rollback()
            raise DatabaseException(f"Database error: {e}")
        finally:
            cursor.close()

    def create_job(
        self,
        job_id: str,
        domain: str,
        status: str = "pending",
        created_at: Optional[str] = None,
    ) -> str:
        """
        Create a new job record.

        Args:
            job_id: Unique job identifier
            domain: Target domain or IP
            status: Job status (default: pending)
            created_at: ISO 8601 timestamp (default: current time)

        Returns:
            job_id of created job
        """
        if created_at is None:
            created_at = datetime.utcnow().isoformat() + "Z"

        with self._cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO jobs (job_id, domain, status, created_at, execution_history, scan_results, error)
                VALUES (?, ?, ?, ?, '[]', NULL, NULL)
                """,
                (job_id, domain, status, created_at),
            )
        return job_id

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a job by ID.

        Args:
            job_id: Job identifier

        Returns:
            Job dictionary or None if not found
        """
        with self._cursor() as cursor:
            cursor.execute(
                "SELECT * FROM jobs WHERE job_id = ?",
                (job_id,),
            )
            row = cursor.fetchone()
            if row:
                return self._row_to_dict(row)
        return None

    def update_job(self, job_id: str, **fields: Any) -> bool:
        """
        Update job fields.

        Args:
            job_id: Job identifier
            **fields: Fields to update (status, scan_results, error)

        Returns:
            True if job was updated, False if not found
        """
        valid_fields = {"status", "scan_results", "error"}
        update_fields = {k: v for k, v in fields.items() if k in valid_fields}

        if not update_fields:
            return False

        set_clause = ", ".join(f"{field} = ?" for field in update_fields.keys())
        values = list(update_fields.values())

        for i, value in enumerate(values):
            if isinstance(value, (dict, list)):
                values[i] = json.dumps(value)

        values.append(job_id)

        with self._cursor() as cursor:
            cursor.execute(
                f"UPDATE jobs SET {set_clause} WHERE job_id = ?",
                values,
            )
            return cursor.rowcount > 0

    def append_execution_step(self, job_id: str, step_data: Dict[str, Any]) -> bool:
        """
        Append a step to the execution history.

        Args:
            job_id: Job identifier
            step_data: Step data dictionary

        Returns:
            True if job was updated, False if not found
        """
        with self._cursor() as cursor:
            cursor.execute(
                "SELECT execution_history FROM jobs WHERE job_id = ?",
                (job_id,),
            )
            row = cursor.fetchone()
            if not row:
                return False

            try:
                history = json.loads(row["execution_history"])
                history.append(step_data)
                cursor.execute(
                    "UPDATE jobs SET execution_history = ? WHERE job_id = ?",
                    (json.dumps(history), job_id),
                )
                return True
            except json.JSONDecodeError:
                return False

    def delete_job(self, job_id: str) -> bool:
        """
        Delete a job by ID.

        Args:
            job_id: Job identifier

        Returns:
            True if job was deleted, False if not found
        """
        with self._cursor() as cursor:
            cursor.execute(
                "DELETE FROM jobs WHERE job_id = ?",
                (job_id,),
            )
            return cursor.rowcount > 0

    def list_jobs(
        self,
        page: int = 1,
        page_size: int = 20,
        status: Optional[str] = None,
        domain_search: Optional[str] = None,
        date_from: Optional[str] = None,
        date_to: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], int, int]:
        """
        List jobs with filtering, sorting, and pagination.

        Args:
            page: Page number (1-indexed)
            page_size: Items per page
            status: Filter by status
            domain_search: Search domains by substring
            date_from: Filter by creation date from (ISO 8601)
            date_to: Filter by creation date to (ISO 8601)

        Returns:
            Tuple of (jobs_list, total_count, total_pages)
        """
        conditions = []
        params = []

        valid_statuses = {"pending", "running", "completed", "failed"}
        if status and status in valid_statuses:
            conditions.append("status = ?")
            params.append(status)
        elif status and status not in valid_statuses:
            raise DatabaseException(
                f"Invalid status '{status}'. Valid values: {', '.join(sorted(valid_statuses))}"
            )

        if domain_search:
            conditions.append("LOWER(domain) LIKE ?")
            params.append(f"%{domain_search.lower()}%")

        if date_from:
            conditions.append("created_at >= ?")
            params.append(date_from)

        if date_to:
            conditions.append("created_at <= ?")
            params.append(date_to)

        where_clause = " AND ".join(conditions) if conditions else "1=1"

        with self._cursor() as cursor:
            cursor.execute(
                f"SELECT COUNT(*) as total FROM jobs WHERE {where_clause}",
                params,
            )
            total = cursor.fetchone()["total"]

        total_pages = (total + page_size - 1) // page_size if page_size > 0 else 1

        offset = (page - 1) * page_size
        with self._cursor() as cursor:
            cursor.execute(
                f"""
                SELECT * FROM jobs
                WHERE {where_clause}
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
                """,
                params + [page_size, offset],
            )
            rows = cursor.fetchall()

        jobs = [self._row_to_dict(row) for row in rows]

        return jobs, total, total_pages

    def _row_to_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        """
        Convert database row to dictionary with JSON deserialization.

        Args:
            row: SQLite Row object

        Returns:
            Dictionary representation of job
        """
        job = dict(row)
        job.pop("id", None)

        if job.get("execution_history"):
            try:
                job["execution_history"] = json.loads(job["execution_history"])
            except json.JSONDecodeError:
                job["execution_history"] = []

        if job.get("scan_results"):
            try:
                job["scan_results"] = json.loads(job["scan_results"])
            except json.JSONDecodeError:
                job["scan_results"] = None

        return job

    def close(self):
        """Close database connection"""
        if self._conn:
            self._conn.close()
            self._conn = None
