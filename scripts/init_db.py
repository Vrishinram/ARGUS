"""Database initialization script for ARGUS Security Gateway."""

import asyncio
from app.config import settings
from app.storage.database import db_manager


async def main():
    print(f"Initializing database at: {settings.db_full_path}")
    await db_manager.init_db()
    print("Database schema successfully generated.")


if __name__ == "__main__":
    asyncio.run(main())
