from flask import Flask, jsonify, request
from flask_cors import CORS

from services.email_parser import parse_email
from services.analysis_repo import save_analysis

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

    analysis_id = save_analysis(parsed_email)

    return jsonify({
        "message": "Email analyzed and saved successfully.",
        "analysis_id": analysis_id,
        "parsed_email": parsed_email,
    })

if __name__ == "__main__":
    app.run(debug=True)