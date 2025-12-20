import sys
import re
from email import policy
from email.parser import BytesParser


URL_REGEX = re.compile(r"https?://[^\s<>()\"']+")


def parse_eml(eml_path: str):
    with open(eml_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    return msg


def extract_sender(msg) -> str:
    sender = msg.get("From")
    return sender if sender else "(No From header found)"


def extract_body_text(msg) -> str:
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    return part.get_content()
                except Exception:
                    pass

        for part in msg.walk():
            if part.get_content_maintype() == "text":
                try:
                    return part.get_content()
                except Exception:
                    pass

        return ""
    else:
        try:
            return msg.get_content()
        except Exception:
            return ""


def extract_urls(text: str) -> list[str]:
    return URL_REGEX.findall(text or "")

def calculate_risk(urls: list[str], sender: str) -> str:
    score = 0
    suspicious_keywords = ["verify", "login", "secure", "update", "account"]

    if urls:
        score += 1

    for url in urls:
        for kw in suspicious_keywords:
            if kw in url.lower():
                score += 1
                break

    if sender and "@" in sender:
        sender_domain = sender.split("@")[-1].strip(">")
        for url in urls:
            if sender_domain not in url:
                score += 1
                break

    if score >= 3:
        return "HIGH"
    elif score == 2:
        return "MEDIUM"
    else:
        return "LOW"


def main():
    if len(sys.argv) != 2:
        print("Usage: python analyzer.py <path_to_email.eml>")
        print("Example: python analyzer.py samples/sample.eml")
        sys.exit(1)

    eml_path = sys.argv[1]
    msg = parse_eml(eml_path)

    sender = extract_sender(msg)
    body = extract_body_text(msg)
    urls = extract_urls(body)
    risk = calculate_risk(urls, sender)


    print("Phishing Email Analyzer (Offline)")
    print("-" * 35)
    print(f"File: {eml_path}")
    print(f"From: {sender}")
    print()

    if urls:
        print("URLs found:")
        for url in urls:
            print(f"- {url}")
    else:
        print("URLs found: none")
    print()
    print(f"Risk Level: {risk}")



if __name__ == "__main__":
    main()
