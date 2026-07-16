import re

URL_PATTERN = r"https?://[^\s<>\"]+"

def extract_urls(text):
    if not text:
        return []

    urls = re.findall(URL_PATTERN, text)

    cleaned_urls = []

    for url in urls:
        cleaned_url = url.rstrip(".,)")
        cleaned_urls.append(cleaned_url)

    return cleaned_urls