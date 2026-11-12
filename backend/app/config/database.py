import logging
from typing import Optional
import certifi
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pymongo import ASCENDING, DESCENDING
from app.config.settings import settings

logger = logging.getLogger("phishguard.database")


class DatabaseManager:
    client: Optional[AsyncIOMotorClient] = None
    db: Optional[AsyncIOMotorDatabase] = None
    is_connected: bool = False
    connection_error: Optional[str] = None

    async def connect_to_database(self) -> None:
        """
        Connect to MongoDB Atlas using AsyncIOMotorClient.
        Handles connection failures gracefully so the server can run and report health status.
        """
        uri = settings.MONGODB_URI.strip()
        if not uri:
            self.is_connected = False
            self.connection_error = "MONGODB_URI is not configured in environment."
            logger.warning("MongoDB URI not provided. Running in offline/disconnected database mode.")
            return

        try:
            logger.info("Connecting to MongoDB Atlas...")
            # Set short server selection timeout (5s) so startup doesn't hang indefinitely on bad network/credentials
            self.client = AsyncIOMotorClient(
                uri,
                tlsCAFile=certifi.where(),
                serverSelectionTimeoutMS=5000,
                connectTimeoutMS=5000,
            )

            # Verify connection with a ping before marking connected and assigning db
            await self.client.admin.command("ping")
            self.db = self.client[settings.DATABASE_NAME]
            self.is_connected = True
            self.connection_error = None
            logger.info("Successfully connected to MongoDB Atlas database '%s'", settings.DATABASE_NAME)

            # Ensure indexes are created
            await self.create_indexes()

        except Exception as exc:
            self.is_connected = False
            self.db = None
            if self.client:
                self.client.close()
                self.client = None
            self.connection_error = str(exc)
            logger.error("Failed to connect to MongoDB Atlas: %s", exc)

    async def close_database_connection(self) -> None:
        """Close MongoDB Atlas connection pool."""
        if self.client:
            self.client.close()
            self.client = None
        self.db = None
        self.is_connected = False
        logger.info("MongoDB Atlas connection closed.")

    async def create_indexes(self) -> None:
        """Create required indexes on collections."""
        if not self.is_connected or self.db is None:
            return

        try:
            # 1. Users collection: unique index on email
            await self.db.users.create_index([("email", ASCENDING)], unique=True, name="idx_user_email_unique")

            # 2. Scans collection: compound and single indexes
            await self.db.scans.create_index([("user_id", ASCENDING)], name="idx_scan_user_id")
            await self.db.scans.create_index([("created_at", DESCENDING)], name="idx_scan_created_at")
            await self.db.scans.create_index([("domain", ASCENDING)], name="idx_scan_domain")
            await self.db.scans.create_index([("classification", ASCENDING)], name="idx_scan_classification")
            await self.db.scans.create_index([("user_id", ASCENDING), ("created_at", DESCENDING)], name="idx_scan_user_created")

            # 3. Reports collection: indexes on user_id, scan_id, created_at
            await self.db.reports.create_index([("user_id", ASCENDING)], name="idx_report_user_id")
            await self.db.reports.create_index([("scan_id", ASCENDING)], name="idx_report_scan_id")
            await self.db.reports.create_index([("created_at", DESCENDING)], name="idx_report_created_at")

            logger.info("Database indexes verified/created successfully.")
        except Exception as exc:
            logger.warning("Error creating database indexes: %s", exc)

    def get_database(self) -> Optional[AsyncIOMotorDatabase]:
        return self.db if self.is_connected else None


db_manager = DatabaseManager()


def get_db() -> Optional[AsyncIOMotorDatabase]:
    """Dependency helper to get the database instance."""
    return db_manager.get_database()

