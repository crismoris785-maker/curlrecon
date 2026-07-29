from typing import Dict

from curlrecon.models import HeaderStatus, SecurityBaseline

SECURITY_HEADERS = {
    "strict-transport-security": "Enforces secure (HTTP over SSL/TLS) connections to the server.",
    "content-security-policy": "Prevents cross-site scripting (XSS), clickjacking and other code injection attacks.",
    "x-frame-options": "Protects against clickjacking attacks.",
    "x-content-type-options": "Prevents MIME-sniffing.",
    "referrer-policy": "Controls how much referrer information (sent via the Referer header) should be included with requests.",
    "permissions-policy": "Provides a mechanism to allow and deny the use of browser features in its own frame, and in content within any <iframe> elements in the document.",
}


def evaluate_security_headers(headers: Dict[str, str]) -> SecurityBaseline:
    headers_lower = {k.lower(): v for k, v in headers.items()}
    baseline = SecurityBaseline()

    for header, description in SECURITY_HEADERS.items():
        if header in headers_lower:
            baseline.headers[header] = HeaderStatus(
                present=True, value=headers_lower[header], description=description
            )
        else:
            baseline.headers[header] = HeaderStatus(
                present=False, value=None, description=description
            )

    return baseline
