
import argparse
import json
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

TOOL_NAME = "Business Verification Security Lab"

HEADERS_TO_CHECK = {
    "Content-Security-Policy": "Medium",
    "Strict-Transport-Security": "Medium",
    "X-Content-Type-Options": "Low",
    "Referrer-Policy": "Low",
    "Permissions-Policy": "Info",
}


def make_finding(severity, title, evidence, recommendation):
    return {
        "severity": severity,
        "title": title,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def demo_report():
    return {
        "tool": TOOL_NAME,
        "mode": "Educational demo",
        "notice": (
            "Hypothetical scenarios, not confirmed Google vulnerabilities."
        ),
        "scenarios": [
            {
                "id": "LAB-01",
                "risk": "High",
                "title": "Verification status trust",
                "problem": (
                    "A fictional server trusts a status sent by the browser."
                ),
                "fix": (
                    "Store verification status on the server and validate "
                    "every state change."
                ),
            },
            {
                "id": "LAB-02",
                "risk": "High",
                "title": "Reusable verification token",
                "problem": (
                    "A fictional system accepts a token more than once."
                ),
                "fix": (
                    "Use short-lived, single-use tokens and invalidate "
                    "them after successful verification."
                ),
            },
            {
                "id": "LAB-03",
                "risk": "High",
                "title": "Missing ownership authorization",
                "problem": (
                    "A logged-in user can try to manage a record they "
                    "do not own."
                ),
                "fix": (
                    "Check server-side permissions for every business "
                    "record and every sensitive action."
                ),
            },
            {
                "id": "LAB-04",
                "risk": "Medium",
                "title": "Incomplete audit logs",
                "problem": (
                    "Important verification events are not recorded."
                ),
                "fix": (
                    "Log the actor, time, target, and outcome without "
                    "recording passwords or secret tokens."
                ),
            },
        ],
    }


def audit_website(url):
    if "://" not in url:
        url = "https://" + url

    parsed = urlparse(url)

    if (
        parsed.scheme not in ("https", "http")
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        raise ValueError("Please enter a valid HTTP or HTTPS URL.")

    if parsed.scheme != "https":
        raise ValueError("Use an HTTPS URL for this passive check.")

    response = requests.get(
        url,
        timeout=10,
        allow_redirects=False,
        headers={"User-Agent": "BusinessVerificationSecurityLab/1.0"},
    )

    findings = []

    for header, severity in HEADERS_TO_CHECK.items():
        value = response.headers.get(header)

        if value:
            findings.append(make_finding(
                "Info",
                f"Header observed: {header}",
                value[:200],
                "Review the configuration; presence alone does not prove "
                "the website is secure.",
            ))
        else:
            findings.append(make_finding(
                severity,
                f"Header not observed: {header}",
                f"{header} was not present in this HTTP response.",
                "Review whether this header is appropriate for the site. "
                "Its absence alone does not prove a vulnerability.",
            ))

    status_code = response.status_code
    response.close()

    return {
        "tool": TOOL_NAME,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": parsed.hostname,
        "scan_type": "Basic passive HTTP header review",
        "http_status": status_code,
        "findings_count": len(findings),
        "limitations": [
            "This is not a complete vulnerability scanner.",
            "Missing headers are not automatically exploitable flaws.",
            "It does not test Google Business Profile verification.",
            "Only test websites you own or are authorized to assess.",
        ],
        "findings": findings,
    }


def main():
    parser = argparse.ArgumentParser(description=TOOL_NAME)
    parser.add_argument("--demo", action="store_true")
    parser.add_argument("--url")
    parser.add_argument("--out", default="report.json")
    args = parser.parse_args()

    if args.demo:
        report = demo_report()
    elif args.url:
        report = audit_website(args.url)
    else:
        parser.error("Use --demo or provide --url.")

    output = json.dumps(report, indent=2, ensure_ascii=False)
    print(output)

    with open(args.out, "w", encoding="utf-8") as file:
        file.write(output + "\n")

    print(f"\nReport saved to: {args.out}")


if __name__ == "__main__":
    main()
      
