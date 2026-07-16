import re

URL_PATTERN = r"https?://[^\s<>\"]+"

def extract_urls(text):
    if not text:
        return []
    
    urls = re.findall(URL_PATTERN, text)
    return urls