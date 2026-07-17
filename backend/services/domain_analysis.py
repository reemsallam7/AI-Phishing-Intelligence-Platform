import ipaddress
from urllib.parse import urlparse

def analyze_url(url):

    parsed_url = urlparse(url)
    scheme = parsed_url.scheme
    domain = parsed_url.netloc.lower()
    path = parsed_url.path
    tld = extract_tld(domain)

    features = {
        "url_length": len(url),
        "dot_count": url.count('.'),
        "hyphen_count": url.count('-'),
        "digit_count": sum(c.isdigit() for c in url),
        "has_https": scheme == "https",
        "is_ip_address": is_ip_address(domain),
    }

    risk_indicators = build_risk_indicators(features)

    return {
        "url": url,
        "domain": domain,
        "scheme": scheme,
        "tld": tld,
        "path": path,
        "features": features,
        "risk_indicators": risk_indicators,
    }

def extract_tld(domain):
        if not domain or '.' not in domain:
            return None
        return domain.split('.')[-1]

def count_digits(text):
        digit_count = 0
        for char in text:
            if char.isdigit():
                digit_count += 1
        return digit_count
    
def is_ip_address(domain):
        try:
            ipaddress.ip_address(domain)
            return True
        except ValueError:
            return False
        
def build_risk_indicators(features):
        indicators =[]

        if features["url_length"] > 75:
            indicators.append("long url length")

        if features["dot_count"] >= 4:
            indicators.append("excessive dots in url")

        if features["hyphen_count"] > 0:
            indicators.append("url contains hyphens")

        if features["digit_count"] > 0:
            indicators.append("url contains digits")

        if not features["has_https"]:
            indicators.append("url doesn't use https")
        
        if features ["is_ip_address"]:
            indicators.append("url uses an IP address instead of a domain")

        return indicators