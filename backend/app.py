from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

@app.get("/health")
def health_check():
    return jsonify({"status": "running"})

@app.post("/analyze")
def analyze_email():
    data = request.get_json()
    email_text = data.get("email", "")
    if not email_text:
        return jsonify({"error": "No email text provided"}), 400
    
    return jsonify({"message": "Email received successfully"})
    

if __name__ == "__main__":
    app.run(debug=True)