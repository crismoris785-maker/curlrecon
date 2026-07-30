import re
from typing import List

# A small subset of common secret patterns for demonstration
SECRET_PATTERNS = {
    "AWS Access Key ID": r"(?i)AKIA[0-9A-Z]{16}",
    "Stripe Standard API Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    "RSA Private Key": r"-----BEGIN RSA PRIVATE KEY-----",
    "Generic API Key / Token": r"(?i)(?:api_key|apikey|auth_token|access_token|secret_key)[\s]*[:=][\s]*[\'\"]([a-zA-Z0-9_\-\.]{16,64})[\'\"]"
}

def extract_secrets(text: str) -> List[str]:
    """
    Scans the given text for known secret patterns and returns a list of identified secrets.
    """
    found_secrets = set()
    if not text:
        return []

    for name, pattern in SECRET_PATTERNS.items():
        matches = re.finditer(pattern, text)
        for match in matches:
            # We don't want to expose the actual secret in the report, just that we found one of a certain type
            # Or we could redact it. Let's redact it to show proof.
            full_match = match.group(0)
            redacted = full_match[:4] + "***" + full_match[-4:] if len(full_match) > 10 else "***"
            found_secrets.add(f"{name} (Redacted: {redacted})")

    return list(found_secrets)
