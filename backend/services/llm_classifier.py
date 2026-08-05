import json

from services.llm_service import LLMServiceError, generate_llm_response


VALID_CLASSIFICATIONS = {"Safe", "Suspicious", "Phishing"}


def classify_email_with_ai(parsed_email):
    prompt = build_classification_prompt(parsed_email)

    try:
        response_text = generate_llm_response(prompt)
        return parse_ai_response(response_text)

    except LLMServiceError as error:
        return build_fallback_result(str(error))


def build_classification_prompt(parsed_email):
    evidence = {
        "sender": parsed_email.get("from"),
        "recipient": parsed_email.get("to"),
        "subject": parsed_email.get("subject"),
        "body": parsed_email.get("body"),
        "urls": parsed_email.get("urls", []),
        "virustotal_results": parsed_email.get("url_reputation", []),
        "domain_analysis": parsed_email.get("url_analysis", []),
    }

    return f"""
You are a cybersecurity analyst helping classify a suspicious email.

Analyze the evidence and return JSON only. Do not include markdown, comments, or extra text.

Use only one of these classifications:
- Safe
- Suspicious
- Phishing

Return this exact JSON shape:
{{
  "classification": "Safe",
  "confidence": 0,
  "explanation": ["reason 1", "reason 2"],
  "recommendations": ["recommendation 1", "recommendation 2"]
}}

Rules:
- confidence must be an integer from 0 to 100.
- explanation must be a list of short human-readable reasons.
- recommendations must be practical security actions.
- Base your decision only on the evidence provided.
- Do not invent URLs, senders, VirusTotal results, or domain findings.
- If evidence is limited, classify conservatively as Suspicious.

Evidence:
{json.dumps(evidence, indent=2)}
""".strip()


def parse_ai_response(response_text):
    try:
        parsed_response = json.loads(response_text)
    except json.JSONDecodeError:
        parsed_response = extract_json_from_text(response_text)

    classification = parsed_response.get("classification", "Suspicious")
    confidence = parsed_response.get("confidence", 50)
    explanation = parsed_response.get("explanation", [])
    recommendations = parsed_response.get("recommendations", [])

    if classification not in VALID_CLASSIFICATIONS:
        classification = "Suspicious"

    if not isinstance(confidence, int):
        confidence = 50

    confidence = max(0, min(confidence, 100))

    if not isinstance(explanation, list):
        explanation = ["The model did not return an explanation in the expected format."]

    if not isinstance(recommendations, list):
        recommendations = ["Review the email carefully before interacting with links."]

    return {
        "classification": classification,
        "confidence": confidence,
        "explanation": explanation,
        "recommendations": recommendations,
        "source": "ollama",
    }


def extract_json_from_text(response_text):
    start_index = response_text.find("{")
    end_index = response_text.rfind("}")

    if start_index == -1 or end_index == -1:
        return build_fallback_result(
            "The local LLM did not return valid JSON."
        )

    json_text = response_text[start_index:end_index + 1]

    try:
        return json.loads(json_text)
    except json.JSONDecodeError:
        return build_fallback_result(
            "The local LLM response contained malformed JSON."
        )


def build_fallback_result(message):
    return {
        "classification": "Suspicious",
        "confidence": 50,
        "explanation": [message],
        "recommendations": [
            "Review the email manually.",
            "Do not click links unless you trust the sender.",
            "Verify suspicious requests through a separate trusted channel.",
        ],
        "source": "fallback",
    }