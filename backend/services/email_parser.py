from email import policy
from email.parser import Parser

from services.url_extractor import extract_urls
from services.performance import create_timings, measure_stage
from services.url_intelligence import analyze_urls

def parse_email(email_text):
    timings = create_timings()

    # Use the email parser to parse the email text
    with measure_stage(timings, "email_parsing"):
        clean_email = email_text.strip()
        email_message = Parser(policy=policy.default).parsestr(clean_email)
        body = extract_body(email_message)
        urls = extract_urls(body)

    with measure_stage(timings, "url_intelligence"):
        url_results = analyze_urls(urls, timings)

    # Extract relevant fields from the email message
    return {
        "from": clean_header(email_message.get("From")),
        "to": clean_header(email_message.get("To")),
        "subject": clean_header(email_message.get("Subject")),
        "body": body,
        "urls": urls,
        "url_reputation": url_results["url_reputation"],
        "url_analysis": url_results["url_analysis"],
        "urlscan_results": url_results["urlscan_results"],
        "performance": timings,
    }


def clean_header(value):
    if value is None:
        return None

    cleaned_value = value.strip()

    if not cleaned_value:
        return None

    return cleaned_value

def extract_body(email_message):
    # Extract the body of the email message
    if email_message.is_multipart():
        # If the email is multipart, get the payload of the first part
        text_part = email_message.get_body(preferencelist=('plain', 'html'))

        if text_part is None:
            return None

        content = text_part.get_content().strip()
        return content if content else None
    
    content = email_message.get_content().strip()
    return content if content else None
