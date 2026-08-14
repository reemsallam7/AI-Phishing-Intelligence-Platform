import os
import time
import logging

import requests


DEFAULT_URLSCAN_BASE_URL = "https://urlscan.io"
logger = logging.getLogger(__name__)


def analyze_urls_with_urlscan(urls):
    results = []

    for url in urls:
        results.append(scan_url_with_urlscan(url))

    return results


def scan_url_with_urlscan(url):
    api_key = os.getenv("URLSCAN_API_KEY")

    if not api_key:
        return build_unavailable_result(url, "URLScan API key is not configured.")

    try:
        submission = submit_url(url, api_key)
        scan_id = submission.get("uuid")

        if not scan_id:
            return build_unavailable_result(url, "URLScan did not return a scan ID.")

        result = poll_scan_result(scan_id, api_key)

        if result is None:
            return build_unavailable_result(url, "URLScan scan did not finish in time.")

        return parse_urlscan_result(url, scan_id, result)

    except requests.Timeout:
        logger.warning("URLScan timeout for URL: %s", url)
        return build_unavailable_result(url, "URLScan analysis timed out.")
    except requests.RequestException as error:
        logger.warning("URLScan unavailable for URL %s: %s", url, error)
        return build_unavailable_result(url, f"URLScan unavailable: {error}")


def submit_url(url, api_key):
    base_url = get_base_url()
    visibility = os.getenv("URLSCAN_VISIBILITY", "unlisted")

    response = requests.post(
        f"{base_url}/api/v1/scan/",
        headers={
            "API-Key": api_key,
            "Content-Type": "application/json",
        },
        json={
            "url": url,
            "visibility": visibility,
            "tags": ["ai-phishing"],
        },
        timeout=int(os.getenv("URLSCAN_SUBMIT_TIMEOUT_SECONDS", "15")),
    )

    if not response.ok:
        raise requests.RequestException(
            f"URLScan rejected submission: {response.status_code} {response.text}"
        )

    return response.json()


def poll_scan_result(scan_id, api_key):
    initial_wait = int(os.getenv("URLSCAN_INITIAL_WAIT_SECONDS", "10"))
    poll_interval = int(os.getenv("URLSCAN_POLL_INTERVAL_SECONDS", "5"))
    max_attempts = int(os.getenv("URLSCAN_MAX_POLL_ATTEMPTS", "6"))

    time.sleep(initial_wait)

    for _ in range(max_attempts):
        response = requests.get(
            f"{get_base_url()}/api/v1/result/{scan_id}/",
            headers={
                "API-Key": api_key,
            },
            timeout=int(os.getenv("URLSCAN_RESULT_TIMEOUT_SECONDS", "15")),
        )

        if response.status_code == 200:
            return response.json()

        if response.status_code == 404:
            time.sleep(poll_interval)
            continue

        if response.status_code == 410:
            return None

        if not response.ok:
            raise requests.RequestException(
                f"URLScan result request failed: {response.status_code} {response.text}"
            )

    return None


def parse_urlscan_result(original_url, scan_id, result):
    page = result.get("page", {})
    task = result.get("task", {})
    verdicts = result.get("verdicts", {})
    overall_verdict = verdicts.get("overall", {})

    return {
        "url": original_url,
        "final_url": page.get("url"),
        "page_title": page.get("title"),
        "country": page.get("country"),
        "ip": page.get("ip"),
        "domain": page.get("domain"),
        "server": page.get("server"),
        "verdict": get_verdict_label(overall_verdict),
        "screenshot_url": f"{get_base_url()}/screenshots/{scan_id}.png",
        "scan_id": scan_id,
        "scan_time": task.get("time"),
        "status": "completed",
    }


def get_verdict_label(verdict):
    if verdict.get("malicious"):
        return "malicious"

    if verdict.get("score", 0) > 0:
        return "suspicious"

    return "clean"


def build_unavailable_result(url, message):
    return {
        "url": url,
        "final_url": None,
        "page_title": None,
        "country": None,
        "ip": None,
        "domain": None,
        "server": None,
        "verdict": None,
        "screenshot_url": None,
        "scan_id": None,
        "scan_time": None,
        "status": "unavailable",
        "message": message,
    }


def get_base_url():
    return os.getenv("URLSCAN_BASE_URL", DEFAULT_URLSCAN_BASE_URL).rstrip("/")
