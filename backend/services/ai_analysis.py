def analyze_email_risk(parsed_email):
    risk_score = 0
    reasons = []

    if not parsed_email.get('from'):
        risk_score += 10
        reasons.append("Email is missing a sender address.")

    if not parsed_email.get('subject'):
        risk_score += 5
        reasons.append("Email is missing a subject line.")

    for reputation in parsed_email.get('reputation', []):
        malicious_count = reputation.get('malicious_count', 0)
        suspicious_count = reputation.get('suspicious_count', 0)

        if malicious_count > 0:
            risk_score += 40
            reasons.append(f"VirusTotal reported {malicious_count} malicious reputation detection(s)")

        if suspicious_count > 0:
            risk_score += 20
            reasons.append(f"VirusTotal reported {suspicious_count} suspicious reputation detection(s)")

    for url_analysis in parsed_email.get('url_analysis', []):
        features = url_analysis.get('features', [])

        if not features.get('has_https', True):
            risk_score += 10
            reasons.append(f"URL doesn't use HTTPS")

        if features.get('is_ip_address', False):
            risk_score += 25
            reasons.append('URL uses an IP address instead of a domain ')

        if features.get('url_length', 0) > 100:
            risk_score += 10
            reasons.append('URL is unusually long')

        if features.get('dot_count', 0) >= 4:
            risk_score += 10
            reasons.append('URL contains many dots or subdomains')

        if features.get('hyphen_count', 0) > 0:
            risk_score += 5
            reasons.append('URL contains hyphens')

    confidence_score = min(risk_score, 100)
    classification = classify_score(confidence_score)

    return {
        "classification": classification,
        "confidence_score": confidence_score,
        "explanation": build_explanation(reasons),
        "reasons": reasons
    }

def classify_score(confidence_score):
    if confidence_score >= 70:
        return "phishing"
    
    elif confidence_score >= 30:
        return "suspicious"
    
    else:
        return "safe"
    
def build_explanation(reasons):
    if not reasons: 
        return "No obvious indicators of phishing were found"
    
    return " ".join(reasons)
