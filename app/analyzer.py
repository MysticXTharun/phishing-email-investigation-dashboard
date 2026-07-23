import hashlib
import ipaddress
import re
from email import policy
from email.parser import Parser
from urllib.parse import urlparse


SUSPICIOUS_WORDS = {
    "urgent",
    "verify",
    "suspended",
    "password",
    "invoice",
    "payment",
    "click here",
    "login",
    "confirm",
    "winner",
    "security alert",
}

SUSPICIOUS_EXTENSIONS = {
    ".exe",
    ".scr",
    ".js",
    ".vbs",
    ".bat",
    ".cmd",
    ".ps1",
    ".iso",
    ".zip",
}


def extract_urls(text: str) -> list[str]:
    pattern = r"https?://[^\s<>'\"\])]+"
    return sorted(set(re.findall(pattern, text, flags=re.IGNORECASE)))


def extract_ips(text: str) -> list[str]:
    candidates = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    valid_ips = []

    for candidate in candidates:
        try:
            ipaddress.ip_address(candidate)
            valid_ips.append(candidate)
        except ValueError:
            continue

    return sorted(set(valid_ips))


def get_authentication_status(message) -> dict:
    authentication = message.get("Authentication-Results", "").lower()

    def status(protocol: str) -> str:
        match = re.search(rf"{protocol}\s*=\s*(pass|fail|softfail|neutral|none)", authentication)
        return match.group(1) if match else "unknown"

    return {
        "spf": status("spf"),
        "dkim": status("dkim"),
        "dmarc": status("dmarc"),
    }


def analyze_email(raw_email: str) -> dict:
    message = Parser(policy=policy.default).parsestr(raw_email)

    sender = str(message.get("From", "Unknown"))
    reply_to = str(message.get("Reply-To", ""))
    subject = str(message.get("Subject", "No Subject"))
    return_path = str(message.get("Return-Path", ""))

    body_parts = []
    attachments = []

    if message.is_multipart():
        for part in message.walk():
            filename = part.get_filename()

            if filename:
                attachments.append(filename)

            if part.get_content_type() == "text/plain":
                try:
                    body_parts.append(part.get_content())
                except Exception:
                    pass
    else:
        try:
            body_parts.append(message.get_content())
        except Exception:
            body_parts.append(str(message.get_payload()))

    body = "\n".join(body_parts)
    complete_text = f"{raw_email}\n{body}"

    urls = extract_urls(complete_text)
    ips = extract_ips(complete_text)

    domains = sorted(
        {
            urlparse(url).hostname
            for url in urls
            if urlparse(url).hostname
        }
    )

    authentication = get_authentication_status(message)
    indicators = []
    risk_score = 0

    sender_domain = sender.split("@")[-1].rstrip(">").lower() if "@" in sender else ""
    reply_domain = reply_to.split("@")[-1].rstrip(">").lower() if "@" in reply_to else ""

    if reply_domain and sender_domain and reply_domain != sender_domain:
        risk_score += 20
        indicators.append("Sender and Reply-To domains do not match")

    for protocol, result in authentication.items():
        if result in {"fail", "softfail"}:
            risk_score += 15
            indicators.append(f"{protocol.upper()} authentication failed")

    lowered_content = f"{subject} {body}".lower()

    matched_words = sorted(
        word for word in SUSPICIOUS_WORDS if word in lowered_content
    )

    if matched_words:
        risk_score += min(len(matched_words) * 5, 20)
        indicators.append(
            "Suspicious language detected: " + ", ".join(matched_words)
        )

    if urls:
        risk_score += min(len(urls) * 5, 15)
        indicators.append(f"{len(urls)} URL(s) detected")

    suspicious_attachments = [
        filename
        for filename in attachments
        if any(filename.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS)
    ]

    if suspicious_attachments:
        risk_score += 25
        indicators.append(
            "Suspicious attachment(s): " + ", ".join(suspicious_attachments)
        )

    if return_path and sender_domain and sender_domain not in return_path.lower():
        risk_score += 10
        indicators.append("Return-Path differs from sender domain")

    risk_score = min(risk_score, 100)

    if risk_score >= 70:
        verdict = "Malicious"
    elif risk_score >= 40:
        verdict = "Suspicious"
    else:
        verdict = "Likely Safe"

    return {
        "subject": subject,
        "sender": sender,
        "reply_to": reply_to or "Not provided",
        "return_path": return_path or "Not provided",
        "message_id": str(message.get("Message-ID", "Not provided")),
        "email_hash": hashlib.sha256(raw_email.encode()).hexdigest(),
        "authentication": authentication,
        "urls": urls,
        "domains": domains,
        "ips": ips,
        "attachments": attachments,
        "indicators": indicators,
        "risk_score": risk_score,
        "verdict": verdict,
    }
