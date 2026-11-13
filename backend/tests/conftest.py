import copy
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from bson import ObjectId
from app.main import app
from app.config.database import db_manager
from app.utils.security import hash_password
from app.utils.dependencies import limiter

# Disable rate limiting during automated test execution
limiter.enabled = False


class MockAsyncCursor:
    def __init__(self, items: List[Dict[str, Any]]):
        self.items = copy.deepcopy(items)
        self.idx = 0

    def sort(self, sort_spec):
        for field, direction in reversed(sort_spec):
            self.items.sort(key=lambda x: x.get(field, ""), reverse=(direction == -1))
        return self

    def skip(self, n: int):
        self.items = self.items[n:]
        return self

    def limit(self, n: int):
        self.items = self.items[:n]
        return self

    def __aiter__(self):
        self.idx = 0
        return self

    async def __anext__(self):
        if self.idx < len(self.items):
            item = self.items[self.idx]
            self.idx += 1
            return item
        raise StopAsyncIteration


class MockInsertOneResult:
    def __init__(self, inserted_id):
        self.inserted_id = inserted_id


class MockDeleteResult:
    def __init__(self, deleted_count: int):
        self.deleted_count = deleted_count


class MockAsyncCollection:
    def __init__(self):
        self.docs: List[Dict[str, Any]] = []

    async def insert_one(self, doc: Dict[str, Any]):
        item = copy.deepcopy(doc)
        if "_id" not in item:
            item["_id"] = ObjectId()
        self.docs.append(item)
        return MockInsertOneResult(item["_id"])

    async def insert_many(self, docs: List[Dict[str, Any]]):
        ids = []
        for d in docs:
            res = await self.insert_one(d)
            ids.append(res.inserted_id)
        return ids

    async def find_one(self, query: Dict[str, Any], *args, **kwargs):
        for doc in self.docs:
            if self._match(doc, query):
                return copy.deepcopy(doc)
        return None

    def find(self, query: Optional[Dict[str, Any]] = None, projection: Optional[Dict[str, Any]] = None):
        matched = []
        q = query or {}
        for doc in self.docs:
            if self._match(doc, q):
                matched.append(copy.deepcopy(doc))
        return MockAsyncCursor(matched)

    async def count_documents(self, query: Dict[str, Any]) -> int:
        count = 0
        for doc in self.docs:
            if self._match(doc, query):
                count += 1
        return count

    async def delete_one(self, query: Dict[str, Any]):
        for idx, doc in enumerate(self.docs):
            if self._match(doc, query):
                self.docs.pop(idx)
                return MockDeleteResult(1)
        return MockDeleteResult(0)

    async def delete_many(self, query: Dict[str, Any]):
        initial_len = len(self.docs)
        self.docs = [d for d in self.docs if not self._match(d, query)]
        return MockDeleteResult(initial_len - len(self.docs))

    async def create_index(self, *args, **kwargs):
        return "mock_index_created"

    def aggregate(self, pipeline: List[Dict[str, Any]]):
        # Lightweight simulation for $group and $match
        results = []
        matched_docs = self.docs
        for stage in pipeline:
            if "$match" in stage:
                matched_docs = [d for d in matched_docs if self._match(d, stage["$match"])]
            elif "$group" in stage:
                groups: Dict[Any, List[Dict[str, Any]]] = {}
                grp_spec = stage["$group"]
                group_key = grp_spec.get("_id", "").replace("$", "")
                for d in matched_docs:
                    key_val = d.get(group_key)
                    groups.setdefault(key_val, []).append(d)

                for g_val, g_docs in groups.items():
                    res = {"_id": g_val, "count": len(g_docs)}
                    if "avg_score" in grp_spec:
                        scores = [x.get("risk_score", 0) for x in g_docs]
                        res["avg_score"] = sum(scores) / len(scores) if scores else 0
                    results.append(res)
        return MockAsyncCursor(results)

    def _match(self, doc: Dict[str, Any], query: Dict[str, Any]) -> bool:
        if not query:
            return True
        for k, v in query.items():
            if k == "$or":
                # Any sub-condition in $or must match
                if not any(self._match(doc, subq) for subq in v):
                    return False
            elif isinstance(v, dict):
                # Operators like $regex, $gte, $lte
                field_val = doc.get(k)
                if "$regex" in v:
                    import re
                    pattern = v["$regex"]
                    if not (isinstance(field_val, str) and re.search(pattern, field_val, re.IGNORECASE)):
                        return False
                if "$gte" in v:
                    if not (field_val and field_val >= v["$gte"]):
                        return False
                if "$lte" in v:
                    if not (field_val and field_val <= v["$lte"]):
                        return False
            else:
                if doc.get(k) != v:
                    return False
        return True


class MockAsyncDatabase:
    def __init__(self):
        self.users = MockAsyncCollection()
        self.scans = MockAsyncCollection()
        self.reports = MockAsyncCollection()

    def __getitem__(self, item: str):
        if not hasattr(self, item):
            setattr(self, item, MockAsyncCollection())
        return getattr(self, item)


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


@pytest_asyncio.fixture
async def mock_db():
    """Provides clean isolated in-memory MongoDB database for testing."""
    test_db = MockAsyncDatabase()
    original_db = db_manager.db
    original_connected = db_manager.is_connected
    original_connect = db_manager.connect_to_database
    original_close = db_manager.close_database_connection

    async def noop():
        pass

    db_manager.connect_to_database = noop
    db_manager.close_database_connection = noop
    db_manager.db = test_db
    db_manager.is_connected = True

    yield test_db

    db_manager.connect_to_database = original_connect
    db_manager.close_database_connection = original_close
    db_manager.db = original_db
    db_manager.is_connected = original_connected


@pytest_asyncio.fixture
async def client(mock_db):
    """Provides AsyncClient configured with ASGI transport."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


@pytest_asyncio.fixture
async def registered_user(mock_db):
    """Creates a sample pre-registered user in the mock database."""
    now = datetime.now(timezone.utc)
    user_dict = {
        "_id": ObjectId("650000000000000000000001"),
        "full_name": "Alex Vance",
        "email": "alex.vance@defense-ops.sec",
        "hashed_password": hash_password("PhishGuard2026!"),
        "created_at": now,
        "updated_at": now,
        "is_active": True,
    }
    await mock_db.users.insert_one(user_dict)
    return user_dict

