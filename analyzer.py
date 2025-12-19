import sys
from email import policy
from email.parser import BytesParser


def extract_sender(eml_path: str) -> str:
    """Read an .eml file and return the sender (From) header."""
    with open(eml_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    sender = msg.get("From")
    return sender if sender else "(No From header found)"


def main():
    if len(sys.argv) != 2:
        print("Usage: python analyzer.py <path_to_email.eml>")
        print("Example: python analyzer.py samples/sample.eml")
        sys.exit(1)

    eml_path = sys.argv[1]
    sender = extract_sender(eml_path)

    print("Phishing Email Analyzer (Offline)")
    print("-" * 35)
    print(f"File: {eml_path}")
    print(f"From: {sender}")


if __name__ == "__main__":
    main()
