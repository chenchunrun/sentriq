# Copyright 2026 CCR <chenchunrun@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Database manager for connection pooling and session management.

Provides async database connectivity with SQLAlchemy.
"""

import asyncio
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, Dict, Optional

from shared.utils.logger import get_logger
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    create_async_engine,
)
from sqlalchemy.orm import sessionmaker

logger = get_logger(__name__)


class DatabaseManager:
    """
    Database connection and session manager.

    Manages connection pooling, session lifecycle, and health checks.

    Attributes:
        database_url: Database connection URL (async)
        engine: SQLAlchemy async engine
        SessionLocal: Session factory
    """

    def __init__(
        self,
        database_url: str,
        pool_size: int = 20,
        max_overflow: int = 40,
        pool_timeout: int = 30,
        pool_recycle: int = 3600,
        echo: bool = False,
    ):
        """
        Initialize database manager.

        Args:
            database_url: Async database URL (postgresql+asyncpg://...)
            pool_size: Connection pool size
            max_overflow: Max overflow connections
            pool_timeout: Connection timeout (seconds)
            pool_recycle: Connection recycle time (seconds)
            echo: Echo SQL queries (debug mode)
        """
        self.database_url = database_url

        # Create async engine with SQLite-compatible options
        # SQLite doesn't support connection pooling, so skip pool params for SQLite
        is_sqlite = database_url.startswith('sqlite')
        engine_kwargs = {
            'pool_pre_ping': True,  # Verify connections before using
            'echo': echo,
        }

        if not is_sqlite:
            # Only add pool parameters for non-SQLite databases
            engine_kwargs.update({
                'pool_size': pool_size,
                'max_overflow': max_overflow,
                'pool_timeout': pool_timeout,
                'pool_recycle': pool_recycle,
            })

        self.engine: AsyncEngine = create_async_engine(
            database_url,
            **engine_kwargs,
        )

        # Create session factory
        self.SessionLocal = sessionmaker(
            self.engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autocommit=False,
            autoflush=False,
        )

        self._initialized = False

    async def initialize(self):
        """Initialize database connection."""
        if self._initialized:
            return

        try:
            # Test connection
            async with self.engine.connect() as conn:
                await conn.execute(text("SELECT 1"))

            self._initialized = True
            logger.info(
                "Database initialized",
                extra={"database_url": self.database_url.split("@")[-1]},  # Hide password
            )
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise

    async def close(self):
        """Close database connections."""
        if not self._initialized:
            return

        try:
            await self.engine.dispose()
            self._initialized = False
            logger.info("Database connections closed")
        except Exception as e:
            logger.error(f"Error closing database: {e}")
            raise

    @asynccontextmanager
    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        """
        Get database session with automatic commit/rollback.

        Yields:
            AsyncSession: Database session

        Example:
            async with db_manager.get_session() as session:
                result = await session.execute(query)
        """
        if not self._initialized:
            await self.initialize()

        async with self.SessionLocal() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()

    async def health_check(self) -> dict[str, Any]:
        """
        Check database health.

        Returns:
            Health check result with status and metrics
        """
        try:
            # Test connection
            async with self.engine.connect() as conn:
                await conn.execute(text("SELECT 1"))

            # Get pool status - check if pool has size attribute
            pool = self.engine.pool
            pool_info = {}

            # Only add pool metrics if the pool type supports them
            if hasattr(pool, 'size'):
                pool_info["pool_size"] = pool.size()
            if hasattr(pool, 'checkedout'):
                pool_info["checked_out_connections"] = pool.checkedout()
            if hasattr(pool, 'overflow'):
                pool_info["overflow"] = pool.overflow()
            if hasattr(pool, 'checkedin'):
                pool_info["checked_in_connections"] = pool.checkedin()

            return {
                "status": "healthy",
                **pool_info,
            }
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return {
                "status": "unhealthy",
                "error": str(e),
            }


# Global database manager instance
db_manager: Optional[DatabaseManager] = None


def get_database_manager() -> DatabaseManager:
    """Get global database manager instance."""
    global db_manager
    if db_manager is None:
        raise RuntimeError("Database not initialized. Call init_database() first.")
    return db_manager


async def init_database(
    database_url: str,
    pool_size: int = 20,
    max_overflow: int = 40,
    echo: bool = False,
) -> DatabaseManager:
    """
    Initialize global database manager.

    Args:
        database_url: Database connection URL
        pool_size: Connection pool size (ignored for SQLite)
        max_overflow: Max overflow connections (ignored for SQLite)
        echo: Echo SQL queries

    Returns:
        DatabaseManager instance
    """
    global db_manager

    if db_manager is not None:
        logger.warning("Database already initialized")
        return db_manager

    # Create database manager - it will handle SQLite pool parameters internally
    db_manager = DatabaseManager(
        database_url=database_url,
        pool_size=pool_size,
        max_overflow=max_overflow,
        echo=echo,
    )

    await db_manager.initialize()
    return db_manager


async def close_database():
    """Close global database manager."""
    global db_manager

    if db_manager is not None:
        await db_manager.close()
        db_manager = None
