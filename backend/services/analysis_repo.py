from datetime import datetime, timezone
import re

from bson import ObjectId
from bson.errors import InvalidId
from pymongo import ASCENDING, DESCENDING
from pymongo.errors import PyMongoError

from services.database import database


scans_collection = database["scans"]


def save_scan(parsed_email, ai_analysis):
    scan_document = build_scan_document(parsed_email, ai_analysis)
    result = scans_collection.insert_one(scan_document)
    return str(result.inserted_id)


def build_scan_document(parsed_email, ai_analysis):
    body = parsed_email.get("body") or ""

    return {
        "sender": parsed_email.get("from"),
        "recipient": parsed_email.get("to"),
        "subject": parsed_email.get("subject"),
        "body_preview": body[:500],
        "urls": parsed_email.get("urls", []),
        "url_reputation": parsed_email.get("url_reputation", []),
        "urlscan_results": parsed_email.get("urlscan_results", []),
        "url_analysis": parsed_email.get("url_analysis", []),
        "ai_analysis": ai_analysis,
        "classification": ai_analysis.get("classification"),
        "confidence": ai_analysis.get("confidence"),
        "summary": ai_analysis.get("summary"),
        "explanation": ai_analysis.get("explanation", []),
        "recommendations": ai_analysis.get("recommendations", []),
        "performance": parsed_email.get("performance", {}),
        "created_at": datetime.now(timezone.utc),
    }


def get_scans(search=None, classification=None, sort="newest"):
    query = build_scan_query(search, classification)
    sort_order = build_sort_order(sort)

    scans = scans_collection.find(query, projection=get_scan_summary_projection()).sort(sort_order)

    return [serialize_scan_summary(scan) for scan in scans]


def get_scan_by_id(scan_id):
    try:
        object_id = ObjectId(scan_id)
    except InvalidId:
        return None

    scan = scans_collection.find_one({"_id": object_id})

    if not scan:
        return None

    return serialize_scan_detail(scan)


def get_dashboard_stats():
    total = scans_collection.count_documents({})
    phishing = scans_collection.count_documents({"classification": "Phishing"})
    suspicious = scans_collection.count_documents({"classification": "Suspicious"})
    safe = scans_collection.count_documents({"classification": "Safe"})

    return {
        "total_scans": total,
        "phishing": phishing,
        "suspicious": suspicious,
        "safe": safe,
        "phishing_percentage": calculate_percentage(phishing, total),
        "suspicious_percentage": calculate_percentage(suspicious, total),
        "safe_percentage": calculate_percentage(safe, total),
        "classification_distribution": [
            {"label": "Phishing", "count": phishing},
            {"label": "Suspicious", "count": suspicious},
            {"label": "Safe", "count": safe},
        ],
    }


def build_scan_query(search, classification):
    query = {}

    if classification and classification != "All":
        query["classification"] = classification

    if search:
        safe_search = re.escape(search)
        query["$or"] = [
            {"sender": {"$regex": safe_search, "$options": "i"}},
            {"subject": {"$regex": safe_search, "$options": "i"}},
            {"urls": {"$regex": safe_search, "$options": "i"}},
        ]

    return query


def build_sort_order(sort):
    if sort == "oldest":
        return [("created_at", 1)]

    if sort == "highest-confidence":
        return [("confidence", -1)]

    if sort == "lowest-confidence":
        return [("confidence", 1)]

    return [("created_at", -1)]


def get_scan_summary_projection():
    return {
        "sender": 1,
        "recipient": 1,
        "subject": 1,
        "urls": 1,
        "classification": 1,
        "confidence": 1,
        "created_at": 1,
    }


def serialize_scan_summary(scan):
    return {
        "id": str(scan["_id"]),
        "sender": scan.get("sender"),
        "recipient": scan.get("recipient"),
        "subject": scan.get("subject"),
        "url_count": len(scan.get("urls", [])),
        "classification": scan.get("classification"),
        "confidence": scan.get("confidence"),
        "created_at": scan.get("created_at").isoformat() if scan.get("created_at") else None,
    }


def serialize_scan_detail(scan):
    return {
        "analysis_id": str(scan["_id"]),
        "created_at": scan.get("created_at").isoformat() if scan.get("created_at") else None,
        "parsed_email": {
            "from": scan.get("sender"),
            "to": scan.get("recipient"),
            "subject": scan.get("subject"),
            "body": scan.get("body_preview"),
            "urls": scan.get("urls", []),
            "url_reputation": scan.get("url_reputation", []),
            "urlscan_results": scan.get("urlscan_results", []),
            "url_analysis": scan.get("url_analysis", []),
            "performance": scan.get("performance", {}),
        },
        "ai_analysis": scan.get("ai_analysis", {}),
    }


def calculate_percentage(value, total):
    if total == 0:
        return 0

    return round((value / total) * 100, 1)


def ensure_scan_indexes():
    scans_collection.create_index(
        [("created_at", DESCENDING)],
        name="scans_created_at",
    )
    scans_collection.create_index(
        [("classification", ASCENDING), ("created_at", DESCENDING)],
        name="scans_classification_created_at",
    )
    scans_collection.create_index(
        [("confidence", DESCENDING)],
        name="scans_confidence",
    )
    scans_collection.create_index(
        [("sender", ASCENDING)],
        name="scans_sender",
    )
    scans_collection.create_index(
        [("subject", ASCENDING)],
        name="scans_subject",
    )
    scans_collection.create_index(
        [("urls", ASCENDING)],
        name="scans_urls",
    )
