from app.analyzer import analyze_email, extract_ips, extract_urls


def test_extract_urls():
    text = "Visit https://example.com/login and http://test.example/page"
    urls = extract_urls(text)

    assert "https://example.com/login" in urls
    assert "http://test.example/page" in urls


def test_extract_valid_ips():
    text = "Received from 185.234.219.45 and invalid 999.999.999.999"
    ips = extract_ips(text)

    assert "185.234.219.45" in ips
    assert "999.999.999.999" not in ips


def test_malicious_email_detection():
    raw_email = """From: Microsoft Security <security@microsoft.example>
Reply-To: attacker@malicious.example
Return-Path: <bounce@malicious.example>
Subject: Urgent - Verify Your Password
Authentication-Results: spf=fail; dkim=fail; dmarc=fail

Your account will be suspended. Click here:
https://malicious.example/login
"""

    result = analyze_email(raw_email)

    assert result["verdict"] == "Malicious"
    assert result["risk_score"] >= 70
    assert result["authentication"]["spf"] == "fail"
    assert result["authentication"]["dkim"] == "fail"
    assert result["authentication"]["dmarc"] == "fail"
    assert "malicious.example" in result["domains"]


def test_safe_email_detection():
    raw_email = """From: Team <team@example.com>
Subject: Weekly Meeting Notes
Authentication-Results: spf=pass; dkim=pass; dmarc=pass

Please find the weekly meeting summary below.
"""

    result = analyze_email(raw_email)

    assert result["verdict"] == "Likely Safe"
    assert result["risk_score"] < 40
