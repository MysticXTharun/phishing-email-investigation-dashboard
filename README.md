# Phishing Email Investigation Dashboard

A SOC-focused web application for analyzing suspicious emails, extracting indicators of compromise, validating email authentication results, and calculating a phishing risk score.

## Features

- Raw email header and body analysis
- SPF, DKIM and DMARC result detection
- Sender, Reply-To and Return-Path comparison
- URL, domain and IP address extraction
- Suspicious attachment detection
- Phishing keyword detection
- Risk scoring from 0–100
- Likely Safe, Suspicious and Malicious verdicts
- Investigation history using SQLite
- REST API and Swagger documentation
- Responsive SOC-style dashboard
- Docker deployment
- Automated pytest coverage

## Technology Stack

- Python
- FastAPI
- SQLite
- Jinja2
- HTML, CSS and JavaScript
- Docker and Docker Compose
- Pytest

## Run with Docker

```bash
git clone https://github.com/MysticXTharun/phishing-email-investigation-dashboard.git
cd phishing-email-investigation-dashboard
docker compose up --build -d
