import sys
sys.path.insert(0, 'backend')
import asyncio
from app.config.database import db_manager, get_db

async def main():
    await db_manager.connect_to_database()
    db = get_db()
    if db is None:
        print("DB connection failed:", db_manager.connection_error)
        return
    res = await db.scans.update_many(
        {"user_id": None},
        {"$set": {"legacy_unowned": True, "quarantined": True}}
    )
    print(f"Quarantined unowned scans - Matched: {res.matched_count}, Modified: {res.modified_count}")

if __name__ == "__main__":
    asyncio.run(main())

