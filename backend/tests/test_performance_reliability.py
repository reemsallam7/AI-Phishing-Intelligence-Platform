import unittest
from unittest.mock import patch

from services.ai_classifier import parse_ai_response
from services.url_extractor import extract_urls
from services.url_intelligence import analyze_urls_with_cache


class PerformanceReliabilityTests(unittest.TestCase):
    def test_url_extraction_removes_duplicates(self):
        text = "Open https://example.com and https://example.com."

        self.assertEqual(extract_urls(text), ["https://example.com"])

    @patch("services.url_intelligence.get_cached_url_result")
    def test_cached_url_result_avoids_external_fetch(self, mock_get_cached):
        mock_get_cached.return_value = {
            "url": "https://example.com",
            "status": "success",
            "cached": True,
        }

        def fetch_function(_url):
            raise AssertionError("External fetch should not run for cached URLs.")

        results = analyze_urls_with_cache(
            ["https://example.com"],
            provider="virustotal",
            fetch_function=fetch_function,
        )

        self.assertTrue(results[0]["cached"])

    @patch("services.url_intelligence.save_url_result")
    @patch("services.url_intelligence.get_cached_url_result")
    def test_external_failure_returns_unavailable_result(
        self,
        mock_get_cached,
        _mock_save_url_result,
    ):
        mock_get_cached.return_value = None

        def fetch_function(_url):
            raise RuntimeError("network failed")

        results = analyze_urls_with_cache(
            ["https://example.com"],
            provider="urlscan",
            fetch_function=fetch_function,
        )

        self.assertEqual(results[0]["status"], "unavailable")

    def test_ai_parser_preserves_valid_model_values(self):
        result = parse_ai_response("""
        {
          "classification": "Phishing",
          "confidence": "94%",
          "summary": "The email contains strong phishing indicators.",
          "explanation": ["A malicious URL was detected."],
          "recommendations": ["Do not click the link."]
        }
        """)

        self.assertEqual(result["classification"], "Phishing")
        self.assertEqual(result["confidence"], 94)
        self.assertEqual(result["explanation"], ["A malicious URL was detected."])
        self.assertEqual(result["recommendations"], ["Do not click the link."])


if __name__ == "__main__":
    unittest.main()
