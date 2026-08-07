from flask import Flask, jsonify, request
from flask_cors import CORS
from pymongo.errors import PyMongoError

from services.ai_classifier import classify_email_with_ai
from services.analysis_repo import (
    get_dashboard_stats,
    get_scan_by_id,
    get_scans,
    save_scan,
)
from services.email_parser import parse_email

app = Flask(__name__)
CORS(app)


@app.get("/health")
def health_check():
    return jsonify({"status": "running"})


@app.post("/analyze")
def analyze_email():
    data = request.get_json()
    email_text = data.get("email", "").strip()

    if not email_text:
        return jsonify({"error": "No email text provided."}), 400

    parsed_email = parse_email(email_text)
    ai_analysis = classify_email_with_ai(parsed_email)

    analysis_id = save_scan(parsed_email, ai_analysis)

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