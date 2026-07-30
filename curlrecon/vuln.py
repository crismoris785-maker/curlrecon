import httpx
from typing import List, Optional
from curlrecon.models import FingerprintMatch

TAKEOVER_SIGNATURES = [
    "There isn't a GitHub Pages site here.",
    "NoSuchBucket",
    "No such app",
    "Heroku | No such app",
    "project not found",
    "The specified bucket does not exist"
]


async def check_cors(client: httpx.AsyncClient, url: str) -> Optional[str]:
    """
    Sends an OPTIONS or GET request with a custom Origin header to check for CORS reflection.
    """
    evil_origin = "https://evil.com"
    try:
        response = await client.get(url, headers={"Origin": evil_origin}, follow_redirects=False)
        acao = response.headers.get("access-control-allow-origin")
        if acao == evil_origin or acao == "*":
            # Check if credentials are allowed for even higher severity
            acac = response.headers.get("access-control-allow-credentials", "").lower()
            if acac == "true" and acao == evil_origin:
                return "Critical CORS Misconfiguration (Reflects Origin + Allows Credentials)"
            return f"CORS Misconfiguration (Allows {acao})"
    except Exception:
        pass
    return None

def check_subdomain_takeover(response_text: str, status_code: int) -> Optional[str]:
    """
    Checks if a 404 response matches known dangling DNS signatures.
    """
    if status_code in (404, 403) and response_text:
        for sig in TAKEOVER_SIGNATURES:
            if sig in response_text:
                return f"Potential Subdomain Takeover ({sig})"
    return None

from curlrecon.db_helper import load_cve_db

def check_cves(fingerprints: List[FingerprintMatch]) -> List[str]:
    """
    Maps detected versions to known CVEs using a local JSON database.
    """
    vulns = []
    cve_db = load_cve_db()
    
    for fp in fingerprints:
        if fp.name in cve_db and fp.version:
            cve = cve_db[fp.name].get(fp.version)
            if cve:
                vulns.append(f"{fp.name} {fp.version} is vulnerable to {cve}")
                
    return vulns
