import json
import re

from services.llm_service import LLMServiceError, generate_llm_response


VALID_CLASSIFICATIONS = {"Safe", "Suspicious", "Phishing"}


def classify_email_with_ai(parsed_email):
    prompt = build_classification_prompt(parsed_email)

    try:
        response_text = generate_llm_response(prompt)
        return parse_ai_response(response_text)

    except LLMServiceError as error:
        return build_fallback_result(str(error))

    except Exception as error:
        return build_fallback_result(f"Unexpected AI classification error: {error}")


def build_classification_prompt(parsed_email):
    evidence = {
        "sender": parsed_email.get("from"),
        "recipient": parsed_email.get("to"),
        "subject": parsed_email.get("subject"),
        "body": parsed_email.get("body"),
        "extracted_urls": parsed_email.get("urls", []),
        "virustotal_results": parsed_email.get("url_reputation", []),
        "domain_analysis": parsed_email.get("url_analysis", []),
        "ip_reputation": parsed_email.get("ip_reputation", []),
        "risk_indicators": collect_risk_indicators(parsed_email),
    }

    return f"""
You are a cybersecurity analyst. Analyze the supplied phishing evidence.

You must return STRICT JSON only. No markdown. No commentary outside JSON.

Required JSON schema:
{{
  "classification": "Safe | Suspicious | Phishing",
  "confidence": 0,
  "summary": "plain English summary",
  "explanation": [
    "specific reason 1",
    "specific reason 2",
    "specific reason 3"
  ],
  "recommendations": [
    "practical action 1",
    "practical action 2",
    "practical action 3"
  ]
}}

Rules:
- Use only these classifications: Safe, Suspicious, Phishing.
- confidence must be an integer from 0 to 100.
- explanation must contain multiple human-readable reasons when evidence exists.
- recommendations must contain practical security actions.
- Do not invent evidence.
- If VirusTotal has malicious detections, treat that as strong phishing evidence.
- If URLs use IP addresses, HTTP, suspicious domains, or risky indicators, explain that.
- If evidence is limited or mixed, classify as Suspicious.
- If no suspicious evidence exists, classify as Safe.

Evidence:
{json.dumps(evidence, indent=2)}
""".strip()


def collect_risk_indicators(parsed_email):
    indicators = []

    for analysis in parsed_email.get("url_analysis", []):
        indicators.extend(analysis.get("risk_indicators", []))

    return indicators


def parse_ai_response(response_text):
    parsed_response = load_json_from_response(response_text)

    classification = normalize_classification(
        parsed_response.get("classification")
    )
    confidence = normalize_confidence(
        parsed_response.get("confidence"),
        classification,
    )
    summary = normalize_text(
        parsed_response.get("summary"),
        build_default_summary(classification, confidence),
    )
    explanation = normalize_string_list(
        parsed_response.get("explanation"),
        ["The model did not provide detailed evidence."],
    )
    recommendations = normalize_string_list(
        parsed_response.get("recommendations"),
        ["Review the email carefully before interacting with links."],
    )

    return {
        "classification": classification,
        "confidence": confidence,
        "summary": summary,
        "explanation": explanation,
        "recommendations": recommendations,
        "source": "ollama",
    }


def load_json_from_response(response_text):
    try:
        return json.loads(response_text)
    except json.JSONDecodeError:
        pass

    json_match = re.search(r"\{.*\}", response_text, re.DOTALL)

    if not json_match:
        raise LLMServiceError("The local LLM did not return JSON.")

    try:
        return json.loads(json_match.group(0))
    except json.JSONDecodeError as error:
        raise LLMServiceError(
            f"The local LLM returned malformed JSON: {error}"
        ) from error


def normalize_classification(value):
    if not isinstance(value, str):
        return "Suspicious"

    cleaned_value = value.strip().title()

    if cleaned_value in VALID_CLASSIFICATIONS:
        return cleaned_value

    return "Suspicious"


def normalize_confidence(value, classification):
    if isinstance(value, int):
        confidence = value
    elif isinstance(value, float):
        confidence = round(value)
    elif isinstance(value, str) and value.strip().rstrip("%").isdigit():
        confidence = int(value.strip().rstrip("%"))
    else:
        confidence = default_confidence_for_classification(classification)

    return max(0, min(confidence, 100))


def default_confidence_for_classification(classification):
    if classification == "Phishing":
        return 85

    if classification == "Suspicious":
        return 60

    return 80


def normalize_text(value, default_value):
    if isinstance(value, str) and value.strip():
        return value.strip()

    return default_value


def normalize_string_list(value, default_value):
    if not isinstance(value, list):
        return default_value

    cleaned_items = []

    for item in value:
        if isinstance(item, str) and item.strip():
            cleaned_items.append(item.strip())

    if cleaned_items:
        return cleaned_items

    return default_value


def build_default_summary(classification, confidence):
    return (
        f"The email was classified as {classification} "
        f"with {confidence}% confidence based on the available evidence."
    )


def build_fallback_result(message):
    return {
        "classification": "Suspicious",
        "confidence": 50,
        "summary": "AI classification could not be completed, so the email should be reviewed manually.",
        "explanation": [message],
        "recommendations": [
            "Review the email manually before clicking any links.",
            "Verify suspicious requests through a trusted channel.",
            "Report the email to your security team if anything looks unusual.",
        ],
        "source": "fallback",
    }