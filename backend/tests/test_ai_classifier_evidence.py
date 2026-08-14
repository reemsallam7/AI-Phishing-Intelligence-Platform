import unittest

from services.ai_classifier import (
    apply_evidence_guardrails,
    build_evidence_report,
    build_classification_prompt,
)


class AIClassifierEvidenceTests(unittest.TestCase):
    def test_legitimate_course_announcement_is_low_risk_with_clean_intel(self):
        parsed_email = {
            "from": "Continuance Learning Center <clc@msa.edu.eg>",
            "to": "cs@msa.edu.eg",
            "subject": None,
            "body": (
                "Cloud Computing course registration is open. "
                "Course price is 2500 EGP for MSA students. "
                "Contact us on WhatsApp for registration details."
            ),
            "urls": ["https://msa.edu.eg/course-registration"],
            "url_reputation": [
                {
                    "url": "https://msa.edu.eg/course-registration",
                    "status": "success",
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 20,
                }
            ],
            "urlscan_results": [
                {
                    "url": "https://msa.edu.eg/course-registration",
                    "status": "completed",
                    "verdict": "clean",
                    "final_url": "https://msa.edu.eg/course-registration",
                }
            ],
            "url_analysis": [
                {
                    "url": "https://msa.edu.eg/course-registration",
                    "features": {
                        "has_https": True,
                        "is_ip_address": False,
                    },
                    "risk_indicators": [],
                }
            ],
        }

        evidence_report = build_evidence_report(parsed_email)
        model_result = {
            "classification": "Suspicious",
            "confidence": 50,
            "summary": "The model was uncertain.",
            "explanation": [
                "Missing subject information may indicate a phishing attempt.",
                "The price of 2500 EGP is unusually low compared to other courses.",
                "A link to register for the course may be malicious.",
            ],
            "recommendations": ["Verify the course manually."],
            "source": "ollama",
        }

        result = apply_evidence_guardrails(model_result, evidence_report)

        self.assertEqual(result["classification"], "Safe")
        self.assertGreaterEqual(result["confidence"], 70)
        self.assertNotIn("missing", " ".join(result["explanation"]).lower())
        self.assertNotIn("unusually low", " ".join(result["explanation"]).lower())

    def test_malicious_threat_intelligence_produces_phishing(self):
        parsed_email = {
            "from": "security@example.com",
            "to": "user@example.com",
            "subject": "Urgent password reset",
            "body": "Reset your password immediately at http://bad.example/login",
            "urls": ["http://bad.example/login"],
            "url_reputation": [
                {
                    "url": "http://bad.example/login",
                    "status": "success",
                    "malicious": 5,
                    "suspicious": 1,
                    "harmless": 0,
                }
            ],
            "urlscan_results": [
                {
                    "url": "http://bad.example/login",
                    "status": "completed",
                    "verdict": "malicious",
                }
            ],
            "url_analysis": [],
        }

        evidence_report = build_evidence_report(parsed_email)

        self.assertEqual(evidence_report["recommended_classification"], "Phishing")
        self.assertGreaterEqual(evidence_report["recommended_confidence"], 80)

    def test_weak_indicators_without_confirmed_malicious_evidence_are_suspicious(self):
        parsed_email = {
            "from": "alerts@example.com",
            "to": "user@example.com",
            "subject": "Urgent account notice",
            "body": "Your account will expire. Login immediately.",
            "urls": [],
            "url_reputation": [],
            "urlscan_results": [],
            "url_analysis": [],
        }

        evidence_report = build_evidence_report(parsed_email)

        self.assertEqual(evidence_report["recommended_classification"], "Suspicious")
        self.assertLess(evidence_report["recommended_confidence"], 80)

    def test_prompt_explicitly_forbids_missing_data_and_unsupported_claims(self):
        prompt = build_classification_prompt({
            "from": None,
            "to": None,
            "subject": None,
            "body": "Course costs 2500 EGP.",
            "urls": [],
        })

        self.assertIn("Do not treat missing data as phishing evidence.", prompt)
        self.assertIn("Do not compare prices", prompt)
        self.assertIn("Weak indicators alone should not produce Phishing.", prompt)


if __name__ == "__main__":
    unittest.main()
