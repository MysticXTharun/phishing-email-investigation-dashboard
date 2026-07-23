# Phishing Email Investigation Dashboard

A SOC-focused application that analyzes suspicious emails, extracts indicators of compromise, checks email authentication results, calculates a risk score, and stores investigation history.

## Project Objective

Phishing emails often impersonate trusted organizations to steal credentials, deliver malware, or redirect users to malicious websites. SOC analysts must inspect email headers, authentication results, links, attachments, and sender information before assigning a verdict.

This project automates the initial static-analysis and triage process.

## Features

- Raw email header and body analysis
- SPF, DKIM, and DMARC result detection
- Sender, Reply-To, and Return-Path comparison
- URL, domain, and IP address extraction
- Suspicious attachment detection
- Phishing keyword detection
- SHA-256 email fingerprint generation
- Risk scoring from 0–100
- Likely Safe, Suspicious, and Malicious verdicts
- Investigation history using SQLite
- REST API with Swagger documentation
- Responsive SOC-style interface
- Docker deployment
- Automated pytest coverage

## Phishing Investigation Workflow

1. Analyst submits the complete raw email.
2. The application parses its headers and body.
3. SPF, DKIM, and DMARC results are extracted.
4. Sender, Reply-To, and Return-Path domains are compared.
5. URLs, domains, IP addresses, and attachments are extracted.
6. Suspicious language and file extensions are detected.
7. A risk score and verdict are generated.
8. Results are stored in SQLite for later review.

## Email Authentication

### SPF

Sender Policy Framework checks whether the sending mail server is authorized to send email for the claimed domain.

### DKIM

DomainKeys Identified Mail uses a digital signature to verify that the email was authorized by the sending domain and was not modified in transit.

### DMARC

Domain-based Message Authentication, Reporting and Conformance applies domain policies using SPF and DKIM results to help prevent email spoofing.

## Indicators Analyzed

| Indicator | Purpose |
|---|---|
| From address | Identifies the displayed sender |
| Reply-To address | Detects replies redirected to another domain |
| Return-Path | Identifies the envelope sender |
| SPF, DKIM and DMARC | Detects authentication failures |
| URLs and domains | Finds possible credential-harvesting links |
| IP addresses | Extracts infrastructure for further investigation |
| Attachments | Detects suspicious executable or script extensions |
| Email language | Detects urgency, account threats, and credential requests |
| SHA-256 hash | Creates a unique fingerprint for the submitted email |

## Risk Classification

| Risk Score | Verdict | Meaning |
|---|---|---|
| 0–39 | Likely Safe | Few or no suspicious indicators |
| 40–69 | Suspicious | Requires additional analyst investigation |
| 70–100 | Malicious | Multiple high-confidence phishing indicators |

The score is influenced by authentication failures, mismatched sender information, suspicious wording, URLs, Return-Path differences, and dangerous attachments.

## Technology Stack

- Python
- FastAPI
- SQLite
- Jinja2
- HTML, CSS, and JavaScript
- Docker and Docker Compose
- Pytest

## Project Structure

```text
phishing-email-investigation-dashboard/
├── app/
│   ├── static/
│   │   ├── css/style.css
│   │   └── js/app.js
│   ├── templates/
│   │   ├── index.html
│   │   └── investigation.html
│   ├── analyzer.py
│   ├── database.py
│   └── main.py
├── data/
├── docs/screenshots/
├── tests/test_analyzer.py
├── compose.yaml
├── Dockerfile
├── requirements.txt
└── README.md
```

## Run with Docker

```bash
git clone https://github.com/MysticXTharun/phishing-email-investigation-dashboard.git
cd phishing-email-investigation-dashboard
docker compose up --build -d
```

Open the dashboard:

```text
http://localhost:8000
```

Open the API documentation:

```text
http://localhost:8000/docs
```

Check application health:

```bash
curl http://localhost:8000/api/health
```

## Run Tests

```bash
docker compose exec phishing-dashboard python -m pytest -v
```

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/` | Dashboard |
| POST | `/analyze` | Analyze and save a raw email |
| GET | `/investigations/{id}` | View investigation results |
| GET | `/api/investigations` | Retrieve investigation history |
| GET | `/api/investigations/{id}` | Retrieve one investigation as JSON |
| GET | `/api/statistics` | Retrieve dashboard statistics |
| GET | `/api/health` | Application health check |
| GET | `/docs` | Swagger API documentation |

## Screenshots

### Dashboard Overview

![Dashboard Overview](docs/screenshots/dashboard-overview.png)

### Investigation Results

![Investigation Results](docs/screenshots/investigation-results.png)

### API Documentation

![API Documentation](docs/screenshots/api-documentation.png)

## Security Limitations

This application performs static analysis only. It does not open URLs, execute attachments, query live threat-intelligence platforms, or guarantee that an email is safe.

In a real SOC investigation, results should be validated using threat intelligence, sandboxing, endpoint telemetry, mail-gateway logs, and analyst review.

## Disclaimer

This project is intended for educational and defensive-security purposes only.
