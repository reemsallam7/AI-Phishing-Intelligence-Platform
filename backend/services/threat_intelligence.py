import base64
import os

import requests


VIRUSTOTAL_URL_REPORT_ENDPOINT = "https://www.virustotal.com/api/v3/urls"


def get_url_reputation(url):
    api_key = os.getenv("VIRUSTOTAL_API_KEY")

    if not api_key:
        return {
            "url": url,
            "status": "error",
            "message": "VirusTotal API key is not configured.",
        }

    url_id = create_virustotal_url_id(url)

    try:
        response = requests.get(
            f"{VIRUSTOTAL_URL_REPORT_ENDPOINT}/{url_id}",
            headers={"x-apikey": api_key},
            timeout=10,
        )
    except requests.RequestException:
        return {
            "url": url,
            "status": "error",
            "message": "Could not connect to VirusTotal.",
        }

    if response.status_code == 404:
        return {
            "url": url,
            "status": "not_found",
            "message": "URL was not found in VirusTotal.",
        }

    if response.status_code == 429:
        return {
            "url": url,
            "status": "rate_limited",
            "message": "VirusTotal rate limit reached. Try again later.",
        }

    if not response.ok:
        return {
            "url": url,
            "status": "error",
            "message": "VirusTotal returned an error.",
        }

    data = response.json()
    attributes = data.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})

    return {
        "url": url,
        "status": "success",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
    }


def create_virustotal_url_id(url):
    encoded_url = base64.urlsafe_b64encode(url.encode()).decode()
    return encoded_url.rstrip("=")