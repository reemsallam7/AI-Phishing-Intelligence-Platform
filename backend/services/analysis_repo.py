from datetime import datetime, timezone

from services.database import database

analyses_collection = database['analyses']

def save_analysis(analysis_document):
    document_to_insert = {
        "parsed_email": analysis_document.get("parsed_email"),
        "ai_analysis": analysis_document.get("ai_analysis"),
        "created_at": datetime.now(timezone.utc),
    }

    result = analyses_collection.insert_one(document_to_insert)

    return str(result.inserted_id)