from email import policy
from email.parser import Parser

from services.url_extractor import extract_urls
from services.threat_intelligence import get_url_reputation
from services.domain_analysis import analyze_url

def parse_email(email_text):
    # Use the email parser to parse the email text
    clean_email = email_text.strip()
    email_message = Parser(policy=policy.default).parsestr(clean_email)
    
    body = extract_body(email_message)
    urls = extract_urls(body)

    url_reputations =[]

    for url in urls:
        reputation = get_url_reputation(url)
        url_reputations.append(reputation)

    url_analysis = []
    for url in urls:
        analysis = analyze_url(url)
        url_analysis.append(analysis)

    # Extract relevant fields from the email message
    return {
        "from": clean_header(email_message.get("From")),
        "to": clean_header(email_message.get("To")),
        "subject": clean_header(email_message.get("Subject")),
        "body": body,
        "urls": urls,
        "url_reputation": url_reputations,
        "url_analysis": url_analysis,
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