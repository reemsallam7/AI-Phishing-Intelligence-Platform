import json
import re
from urllib.parse import urlparse

from services.llm_service import LLMServiceError, generate_llm_response


VALID_CLASSIFICATIONS = {"Safe", "Suspicious", "Phishing"}


def classify_email_with_ai(parsed_email):
    evidence_report = build_evidence_report(parsed_email)
    prompt = build_classification_prompt(parsed_email, evidence_report)

    try:
        response_text = generate_llm_response(prompt)
        ai_result = parse_ai_response(response_text)
        return apply_evidence_guardrails(ai_result, evidence_report)

    except LLMServiceError as error:
        return build_fallback_result(str(error))

    except Exception as error:
        return build_fallback_result(f"Unexpected AI classification error: {error}")


def build_evidence_report(parsed_email):
    strong_indicators = []
    weak_indicators = []
    clean_indicators = []
    neutral_context = []
    unavailable_information = []

    add_missing_context(parsed_email, unavailable_information)
    add_virustotal_evidence(parsed_email, strong_indicators, clean_indicators, unavailable_information)
    add_urlscan_evidence(parsed_email, strong_indicators, weak_indicators, clean_indicators, unavailable_information)
    add_domain_evidence(parsed_email, weak_indicators, clean_indicators)
    add_body_language_evidence(parsed_email, weak_indicators)
    add_url_context(parsed_email, neutral_context, clean_indicators)

    recommended_classification = recommend_classification(
        strong_indicators,
        weak_indicators,
        clean_indicators,
    )
    recommended_confidence = calculate_evidence_confidence(
        recommended_classification,
        strong_indicators,
        weak_indicators,
        clean_indicators,
    )

    return {
        "strong_indicators": strong_indicators,
        "weak_indicators": weak_indicators,
        "clean_indicators": clean_indicators,
        "neutral_context": neutral_context,
        "unavailable_information": unavailable_information,
        "recommended_classification": recommended_classification,
        "recommended_confidence": recommended_confidence,
    }


def add_missing_context(parsed_email, unavailable_information):
    fields = {
        "from": "Sender",
        "to": "Recipient",
        "subject": "Subject",
        "body": "Email body",
    }

    for field, label in fields.items():
        if not parsed_email.get(field):
            unavailable_information.append(f"{label} is not available.")


def add_virustotal_evidence(parsed_email, strong_indicators, clean_indicators, unavailable_information):
    results = parsed_email.get("url_reputation", [])

    for result in results:
        url = result.get("url", "URL not available")
        status = result.get("status")
        malicious = result.get("malicious", 0) or 0
        suspicious = result.get("suspicious", 0) or 0
        harmless = result.get("harmless", 0) or 0

        if status == "success":
            if malicious > 0:
                strong_indicators.append(
                    f"VirusTotal reported {malicious} malicious detection(s) for {url}."
                )
            elif suspicious > 0:
                strong_indicators.append(
                    f"VirusTotal reported {suspicious} suspicious detection(s) for {url}."
                )
            elif harmless > 0:
                clean_indicators.append(
                    f"VirusTotal did not report malicious detections for {url}."
                )
        elif status:
            unavailable_information.append(
                f"VirusTotal result for {url} is {status}."
            )


def add_urlscan_evidence(
    parsed_email,
    strong_indicators,
    weak_indicators,
    clean_indicators,
    unavailable_information,
):
    results = parsed_email.get("urlscan_results", [])

    for result in results:
        url = result.get("url", "URL not available")
        status = result.get("status")
        verdict = result.get("verdict")
        final_url = result.get("final_url")

        if status != "completed":
            unavailable_information.append(f"URLScan result for {url} is not available.")
            continue

        if verdict == "malicious":
            strong_indicators.append(f"URLScan marked {url} as malicious.")
        elif verdict == "suspicious":
            strong_indicators.append(f"URLScan marked {url} as suspicious.")
        elif verdict == "clean":
            clean_indicators.append(f"URLScan did not report malicious behavior for {url}.")

        if final_url and final_url != url:
            weak_indicators.append(
                f"URLScan observed a redirect from {url} to {final_url}."
            )


def add_domain_evidence(parsed_email, weak_indicators, clean_indicators):
    analyses = parsed_email.get("url_analysis", [])

    for analysis in analyses:
        url = analysis.get("url", "URL not available")
        features = analysis.get("features", {})
        indicators = analysis.get("risk_indicators", [])

        if features.get("is_ip_address"):
            weak_indicators.append(f"{url} uses an IP address instead of a domain.")

        if features.get("has_https") is False:
            weak_indicators.append(f"{url} does not use HTTPS.")

        for indicator in indicators:
            if indicator in {"url uses an IP address instead of a domain", "url doesn't use https"}:
                continue

            weak_indicators.append(f"{url}: {indicator}.")

        if features.get("has_https") and not indicators:
            clean_indicators.append(f"{url} uses HTTPS and has no simple domain risk indicators.")


def add_body_language_evidence(parsed_email, weak_indicators):
    body = (parsed_email.get("body") or "").lower()
    subject = (parsed_email.get("subject") or "").lower()
    text = f"{subject} {body}"

    urgency_terms = ["urgent", "immediately", "locked", "suspended", "expire", "final notice"]
    credential_terms = ["password", "login", "verify your account", "reset your account"]
    payment_terms = ["payment", "invoice", "bank transfer", "wallet"]

    if contains_any(text, urgency_terms):
        weak_indicators.append("The email uses urgency or time-pressure language.")

    if contains_any(text, credential_terms):
        weak_indicators.append("The email references account access or credential-related action.")

    if contains_any(text, payment_terms):
        weak_indicators.append("The email references payment or financial action.")


def add_url_context(parsed_email, neutral_context, clean_indicators):
    urls = parsed_email.get("urls", [])

    if not urls:
        neutral_context.append("No URLs were provided for URL reputation analysis.")
        return

    neutral_context.append(f"The email contains {len(urls)} extracted URL(s).")

    if all_urls_have_clean_threat_intelligence(parsed_email):
        clean_indicators.append("Available URL threat-intelligence results are clean.")


def all_urls_have_clean_threat_intelligence(parsed_email):
    reputations = parsed_email.get("url_reputation", [])
    urlscan_results = parsed_email.get("urlscan_results", [])

    if not reputations and not urlscan_results:
        return False

    vt_clean = all(
        result.get("status") == "success"
        and (result.get("malicious", 0) or 0) == 0
        and (result.get("suspicious", 0) or 0) == 0
        for result in reputations
    ) if reputations else True

    urlscan_clean = all(
        result.get("status") == "completed"
        and result.get("verdict") == "clean"
        for result in urlscan_results
    ) if urlscan_results else True

    return vt_clean and urlscan_clean


def recommend_classification(strong_indicators, weak_indicators, clean_indicators):
    if strong_indicators:
        return "Phishing"

    if weak_indicators:
        return "Suspicious"

    if clean_indicators:
        return "Safe"

    return "Safe"


def calculate_evidence_confidence(classification, strong_indicators, weak_indicators, clean_indicators):
    if classification == "Phishing":
        confidence = 80 + min(len(strong_indicators) * 5, 15)
        return min(confidence, 95)

    if classification == "Suspicious":
        confidence = 55 + min(len(weak_indicators) * 5, 20)

        if clean_indicators:
            confidence -= min(len(clean_indicators) * 5, 15)

        return max(45, min(confidence, 75))

    confidence = 70 + min(len(clean_indicators) * 5, 20)

    if weak_indicators:
        confidence -= min(len(weak_indicators) * 8, 25)

    return max(55, min(confidence, 90))


def build_classification_prompt(parsed_email, evidence_report=None):
    if evidence_report is None:
        evidence_report = build_evidence_report(parsed_email)

    evidence = {
        "sender": parsed_email.get("from") or "Not available",
        "recipient": parsed_email.get("to") or "Not available",
        "subject": parsed_email.get("subject") or "Not available",
        "body": parsed_email.get("body") or "Not available",
        "extracted_urls": parsed_email.get("urls", []),
        "virustotal_results": parsed_email.get("url_reputation", []),
        "domain_analysis": parsed_email.get("url_analysis", []),
        "urlscan_results": parsed_email.get("urlscan_results", []),
        "ip_reputation": parsed_email.get("ip_reputation", []),
        "evidence_report": evidence_report,
    }

    return f"""
You are a cybersecurity analyst. Classify the email using ONLY the supplied evidence.

Return STRICT JSON only. No markdown. No commentary outside JSON.

Required JSON schema:
{{
  "classification": "Safe | Suspicious | Phishing",
  "confidence": 0,
  "summary": "plain English summary",
  "explanation": [
    "specific evidence-based reason 1",
    "specific evidence-based reason 2"
  ],
  "recommendations": [
    "practical action 1",
    "practical action 2"
  ]
}}

Evidence hierarchy:
- Strong indicators can justify Phishing: VirusTotal malicious/suspicious detections, URLScan malicious/suspicious verdicts, confirmed malicious IP/domain evidence, suspicious redirects supported by URLScan, or confirmed threat-intelligence findings.
- Weak indicators can justify Suspicious: urgency, unusual wording, action requests, HTTP URLs, IP-address URLs, long URLs, many subdomains, or other structural URL concerns.
- Neutral context must NOT increase risk: missing fields, no attachment, no URL, no subject, no recipient, no domain information, contact numbers, WhatsApp numbers, prices, course announcements, registration links, payment links, or attachments by themselves.
- Clean threat intelligence should reduce suspicion: clean VirusTotal and clean URLScan results are positive evidence.

Strict rules:
- Do not invent external facts.
- Do not compare prices, reputations, policies, ownership, legitimacy, or previous incidents unless explicitly present in the evidence.
- Do not claim a link is malicious merely because it is a registration, payment, course, contact, or login link.
- Do not treat missing data as phishing evidence.
- Weak indicators alone should not produce Phishing.
- If there are no meaningful malicious indicators and available threat intelligence is clean, classify as Safe.
- If evidence is concerning but not confirmed malicious, classify as Suspicious.
- If strong threat-intelligence evidence is present, classify as Phishing.
- Confidence must reflect the evidence strength and should generally follow evidence_report.recommended_confidence unless you have evidence-based reason to adjust slightly.
- Explanation must cite only items from strong_indicators, weak_indicators, or clean_indicators.
- If information is unavailable, either omit it from explanation or say it is not available without treating it as suspicious.

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


def apply_evidence_guardrails(ai_result, evidence_report):
    guarded_result = ai_result.copy()
    recommended_classification = evidence_report["recommended_classification"]
    recommended_confidence = evidence_report["recommended_confidence"]

    if should_override_classification(guarded_result["classification"], evidence_report):
        guarded_result["classification"] = recommended_classification
        guarded_result["confidence"] = recommended_confidence
        guarded_result["summary"] = build_guardrail_summary(evidence_report)
        guarded_result["explanation"] = build_guardrail_explanation(evidence_report)
        guarded_result["source"] = "ollama_guarded"
        return guarded_result

    if guarded_result["confidence"] == 50 and guarded_result["source"] != "fallback":
        guarded_result["confidence"] = recommended_confidence

    guarded_result["explanation"] = filter_supported_explanations(
        guarded_result["explanation"],
        evidence_report,
    )

    if not guarded_result["explanation"]:
        guarded_result["explanation"] = build_guardrail_explanation(evidence_report)

    return guarded_result


def should_override_classification(classification, evidence_report):
    strong_indicators = evidence_report["strong_indicators"]
    weak_indicators = evidence_report["weak_indicators"]
    clean_indicators = evidence_report["clean_indicators"]

    if classification == "Phishing" and not strong_indicators:
        return True

    if classification == "Suspicious" and not strong_indicators and not weak_indicators and clean_indicators:
        return True

    return False


def build_guardrail_summary(evidence_report):
    classification = evidence_report["recommended_classification"]
    confidence = evidence_report["recommended_confidence"]

    if classification == "Phishing":
        return "The email has strong threat-intelligence evidence consistent with phishing."

    if classification == "Suspicious":
        return "The email has concerning signals, but no confirmed malicious indicator strong enough for a phishing classification."

    return (
        "No meaningful malicious indicators were found, and available threat-intelligence "
        f"evidence supports a low-risk classification with {confidence}% confidence."
    )


def build_guardrail_explanation(evidence_report):
    if evidence_report["strong_indicators"]:
        return evidence_report["strong_indicators"]

    if evidence_report["weak_indicators"]:
        return evidence_report["weak_indicators"]

    if evidence_report["clean_indicators"]:
        return evidence_report["clean_indicators"]

    return ["No meaningful malicious indicators were found in the available evidence."]


def filter_supported_explanations(explanations, evidence_report):
    supported_facts = " ".join(
        evidence_report["strong_indicators"]
        + evidence_report["weak_indicators"]
        + evidence_report["clean_indicators"]
    ).lower()

    filtered = []

    for explanation in explanations:
        normalized = explanation.lower()

        if mentions_missing_as_risk(normalized):
            continue

        if contains_unsupported_claim(normalized):
            continue

        if any(word in supported_facts for word in important_words(normalized)):
            filtered.append(explanation)

    return filtered


def mentions_missing_as_risk(text):
    return "missing" in text and any(
        phrase in text
        for phrase in ["phishing", "suspicious", "risk", "malicious", "attempt"]
    )


def contains_unsupported_claim(text):
    unsupported_terms = [
        "unusually low",
        "compared to other",
        "reputation",
        "policy",
        "owned by",
        "previous incident",
        "known for",
        "does not match organization",
    ]

    return any(term in text for term in unsupported_terms)


def important_words(text):
    return [
        word
        for word in re.findall(r"[a-z0-9]+", text)
        if len(word) > 4
    ]


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


def contains_any(text, terms):
    return any(term in text for term in terms)
