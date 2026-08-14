from datetime import datetime, timedelta, timezone
import os

from pymongo import ASCENDING

from services.database import database


url_cache_collection = database["url_cache"]


def get_cache_ttl_hours():
    return int(os.getenv("URL_CACHE_TTL_HOURS", "24"))


def get_cached_url_result(url, provider):
    cutoff = datetime.now(timezone.utc) - timedelta(hours=get_cache_ttl_hours())

    cached_result = url_cache_collection.find_one({
        "url": url,
        "provider": provider,
        "created_at": {"$gte": cutoff},
    })

    if not cached_result:
        return None

    result = cached_result.get("result", {}).copy()
    result["cached"] = True
    return result


def save_url_result(url, provider, result):
    url_cache_collection.update_one(
        {
            "url": url,
            "provider": provider,
        },
        {
            "$set": {
                "url": url,
                "provider": provider,
                "result": result,
                "created_at": datetime.now(timezone.utc),
            }
        },
        upsert=True,
    )


def ensure_url_cache_indexes():
    url_cache_collection.create_index(
        [("url", ASCENDING), ("provider", ASCENDING)],
        unique=True,
        name="url_provider_unique",
    )
    url_cache_collection.create_index(
        [("created_at", ASCENDING)],
        name="url_cache_created_at",
    )
