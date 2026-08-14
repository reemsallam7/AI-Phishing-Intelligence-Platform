import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

from services.domain_analysis import analyze_url
from services.performance import measure_stage
from services.threat_intelligence import get_url_reputation
from services.url_cache_repo import get_cached_url_result, save_url_result
from services.urlscan_service import scan_url_with_urlscan


logger = logging.getLogger(__name__)


def analyze_urls(urls, timings=None):
    unique_urls = list(dict.fromkeys(urls))

    if timings is None:
        timings = {}

    with measure_stage(timings, "virustotal"):
        url_reputation = analyze_urls_with_cache(
            unique_urls,
            provider="virustotal",
            fetch_function=get_url_reputation,
        )

    with measure_stage(timings, "urlscan"):
        urlscan_results = analyze_urls_with_cache(
            unique_urls,
            provider="urlscan",
            fetch_function=scan_url_with_urlscan,
        )

    with measure_stage(timings, "domain_analysis"):
        url_analysis = analyze_domains(unique_urls)

    return {
        "url_reputation": url_reputation,
        "urlscan_results": urlscan_results,
        "url_analysis": url_analysis,
    }


def analyze_urls_with_cache(urls, provider, fetch_function):
    cached_results = {}
    urls_to_fetch = []

    for url in urls:
        try:
            cached_result = get_cached_url_result(url, provider)
        except Exception as error:
            logger.warning("Could not read %s cache for %s: %s", provider, url, error)
            cached_result = None

        if cached_result:
            cached_results[url] = cached_result
        else:
            urls_to_fetch.append(url)

    fetched_results = fetch_urls_concurrently(urls_to_fetch, provider, fetch_function)
    results_by_url = {**cached_results, **fetched_results}

    return [
        results_by_url.get(url, build_unavailable_result(url, provider))
        for url in urls
    ]


def fetch_urls_concurrently(urls, provider, fetch_function):
    if not urls:
        return {}

    max_workers = int(os.getenv("URL_ANALYSIS_MAX_WORKERS", "3"))
    results = {}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {
            executor.submit(fetch_and_cache_url, url, provider, fetch_function): url
            for url in urls
        }

        for future in as_completed(future_to_url):
            url = future_to_url[future]

            try:
                results[url] = future.result()
            except Exception as error:
                logger.warning("%s analysis failed for %s: %s", provider, url, error)
                results[url] = build_unavailable_result(url, provider)

    return results


def fetch_and_cache_url(url, provider, fetch_function):
    result = fetch_function(url)

    if result.get("status") in {"success", "completed", "not_found"}:
        cacheable_result = result.copy()
        cacheable_result["cached"] = False

        try:
            save_url_result(url, provider, cacheable_result)
        except Exception as error:
            logger.warning("Could not save %s cache for %s: %s", provider, url, error)

        return cacheable_result

    return result


def analyze_domains(urls):
    results = []

    for url in urls:
        try:
            results.append(analyze_url(url))
        except Exception as error:
            logger.warning("Domain analysis failed for %s: %s", url, error)
            results.append({
                "url": url,
                "status": "unavailable",
                "message": "Domain analysis unavailable.",
                "features": {},
                "risk_indicators": [],
            })

    return results


def build_unavailable_result(url, provider):
    return {
        "url": url,
        "status": "unavailable",
        "message": f"{provider} analysis unavailable.",
    }
