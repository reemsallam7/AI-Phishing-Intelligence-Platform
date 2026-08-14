import logging

from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_cors import CORS
from pymongo.errors import PyMongoError

load_dotenv()

from services.ai_classifier import classify_email_with_ai
from services.analysis_repo import (
    ensure_scan_indexes,
    get_dashboard_stats,
    get_scan_by_id,
    get_scans,
    save_scan,
)
from services.email_parser import parse_email
from services.performance import measure_stage
from services.url_cache_repo import ensure_url_cache_indexes

app = Flask(__name__)
CORS(app)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger(__name__)


def initialize_database_indexes():
    try:
        ensure_scan_indexes()
        ensure_url_cache_indexes()
        logger.info("MongoDB indexes are ready.")
    except PyMongoError as error:
        logger.warning("Could not create MongoDB indexes: %s", error)


initialize_database_indexes()


@app.get("/health")
def health_check():
    return jsonify({"status": "running"})


@app.post("/analyze")
def analyze_email():
    data = request.get_json()
    email_text = data.get("email", "").strip()

    if not email_text:
        return jsonify({"error": "No email text provided."}), 400

    logger.info("Analysis started. email_length=%s", len(email_text))
    timings = {}

    try:
        with measure_stage(timings, "analysis_pipeline"):
            parsed_email = parse_email(email_text)

            with measure_stage(timings, "ollama"):
                ai_analysis = classify_email_with_ai(parsed_email)

            parsed_email["performance"] = {
                **parsed_email.get("performance", {}),
                **timings,
            }

            with measure_stage(parsed_email["performance"], "mongodb_save"):
                analysis_id = save_scan(parsed_email, ai_analysis)

    except PyMongoError:
        logger.exception("Database failure while saving completed analysis.")
        return jsonify({"error": "Analysis completed, but saving failed."}), 500
    except Exception:
        logger.exception("Unexpected analysis failure.")
        return jsonify({"error": "Unexpected backend error during analysis."}), 500

    logger.info(
        "Analysis completed. analysis_id=%s timings=%s",
        analysis_id,
        parsed_email.get("performance", {}),
    )

    return jsonify({
        "message": "Email analyzed and saved successfully.",
        "analysis_id": analysis_id,
        "parsed_email": parsed_email,
        "ai_analysis": ai_analysis,
    })


@app.get("/api/scans")
def list_scans():
    search = request.args.get("search")
    classification = request.args.get("classification", "All")
    sort = request.args.get("sort", "newest")

    try:
        scans = get_scans(
            search=search,
            classification=classification,
            sort=sort,
        )

        return jsonify({"scans": scans})

    except PyMongoError:
        return jsonify({"error": "Could not retrieve scans."}), 500


@app.get("/api/scans/<scan_id>")
def get_scan(scan_id):
    try:
        scan = get_scan_by_id(scan_id)

        if scan is None:
            return jsonify({"error": "Scan not found."}), 404

        return jsonify(scan)

    except PyMongoError:
        return jsonify({"error": "Could not retrieve scan."}), 500


@app.get("/api/dashboard/stats")
def dashboard_stats():
    try:
        stats = get_dashboard_stats()
        return jsonify(stats)

    except PyMongoError:
        return jsonify({"error": "Could not retrieve dashboard statistics."}), 500


if __name__ == "__main__":
    app.run(debug=True)
