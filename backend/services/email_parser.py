from email import policy
from email.parser import Parser

from services.url_extractor import extract_urls

def parse_email(email_text):
    # Use the email parser to parse the email text
    clean_email = email_text.strip()
    email_message = Parser(policy=policy.default).parsestr(clean_email)
    
    body = extract_body(email_message)
    # Extract relevant fields from the email message
    return {
        "from": clean_header(email_message.get("From")),
        "to": clean_header(email_message.get("To")),
        "subject": clean_header(email_message.get("Subject")),
        "body": body,
        "urls": extract_urls(body)
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