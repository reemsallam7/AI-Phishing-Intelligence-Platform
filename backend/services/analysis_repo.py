from datetime import datetime, timezone

from services.database import database

analyses_collection = database['analyses']

def save_analysis(parsed_email):
    analysis_data = {
        "parsed_email": parsed_email,
        "timestamp": datetime.now(timezone.utc)
    }

    result = analyses_collection.insert_one(analysis_data)
    return str(result.inserted_id)