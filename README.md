
# Business Verification Security Lab

## About
An educational cybersecurity project for reviewing website security and studying ways to protect business verification workflows.

## Features
- Review common HTTP security headers.
- Generate security reports in JSON format.
- Study hypothetical verification weaknesses.
- Recommend defensive security improvements.

## Requirements
- Python 3.10 or later.
- Install the required package:

```bash
pip install -r requirements.txt
```

## Run the Demo

```bash
python app.py --demo --out demo-report.json
```

## Review an Authorized Website

```bash
python app.py --url https://example.com --out report.json
```

Only assess websites you own or have explicit permission to test.

## Important Note
This is an educational prototype. It does not test or bypass Google's internal Business Profile verification system. The scenarios are hypothetical, not confirmed Google vulnerabilities.
