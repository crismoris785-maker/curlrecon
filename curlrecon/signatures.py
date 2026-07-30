import re
from typing import Dict, List, Optional, Pattern, Tuple

from bs4 import BeautifulSoup

from curlrecon.models import FingerprintMatch, ResponseData


class Signature:
    def __init__(
        self,
        category: str,
        name: str,
        headers: Dict[str, str] = None,
        cookies: Dict[str, str] = None,
        html_patterns: List[str] = None,
        meta_tags: Dict[str, str] = None,
    ):
        self.category = category
        self.name = name
        self.headers = {
            k.lower(): re.compile(v, re.IGNORECASE) for k, v in (headers or {}).items()
        }
        self.cookies = {
            k.lower(): re.compile(v, re.IGNORECASE) for k, v in (cookies or {}).items()
        }
        self.html_patterns = [
            re.compile(p, re.IGNORECASE) for p in (html_patterns or [])
        ]
        self.meta_tags = {
            k.lower(): re.compile(v, re.IGNORECASE)
            for k, v in (meta_tags or {}).items()
        }


SIGNATURES = [
    # CMS
    Signature(
        "CMS",
        "WordPress",
        html_patterns=[r"wp-content/themes", r"wp-content/plugins"],
        meta_tags={"generator": r"WordPress\s*([\d.]+)"},
    ),
    Signature(
        "CMS",
        "Drupal",
        headers={"X-Generator": r"Drupal\s*([\d.]+)"},
        html_patterns=[r"sites/all/themes", r"sites/all/modules"],
    ),
    Signature("CMS", "Laravel", cookies={"laravel_session": r".*"}),
    Signature("CMS", "Django", cookies={"csrftoken": r".*"}),
    Signature(
        "Framework",
        "Next.js",
        headers={"x-powered-by": r"Next\.js"},
        html_patterns=[r"/_next/static/"],
    ),
    Signature(
        "Framework",
        "React",
        html_patterns=[r"data-reactroot", r"__REACT_DEVTOOLS_GLOBAL_HOOK__"],
    ),
    Signature(
        "Framework",
        "Vue",
        html_patterns=[r"data-v-[a-zA-Z0-9]+", r"__VUE_DEVTOOLS_GLOBAL_HOOK__"],
    ),
    # Infrastructure / Server
    Signature("Server", "Nginx", headers={"server": r"nginx(?:/([\d.]+))?"}),
    Signature("Server", "Apache", headers={"server": r"apache(?:/([\d.]+))?"}),
    # CDN / WAF
    Signature("CDN", "Cloudflare", headers={"server": r"cloudflare", "cf-ray": r".*"}),
    Signature(
        "CDN",
        "AWS CloudFront",
        headers={"x-amz-cf-id": r".*", "x-cache": r"(Hit|Miss) from cloudfront"},
    ),
    Signature("CDN", "Akamai", headers={"x-akamai-request-id": r".*"}),
    Signature("WAF", "Imperva", headers={"x-iinfo": r".*", "incap_ses_.*": r".*"}),
]


def analyze_response(response: ResponseData) -> List[FingerprintMatch]:
    matches = []
    headers_lower = {k.lower(): v for k, v in response.headers.items()}

    soup = BeautifulSoup(response.text, "html.parser")
    meta_tags_extracted = {}
    for meta in soup.find_all("meta"):
        name = meta.get("name")
        content = meta.get("content")
        if name and content:
            meta_tags_extracted[name.lower()] = content

    for sig in SIGNATURES:
        matched = False
        version = None
        
        # Check headers
        for h_key, h_pattern in sig.headers.items():
            if h_key in headers_lower:
                match = h_pattern.search(headers_lower[h_key])
                if match:
                    matched = True
                    if match.groups(): version = match.group(1)
                    break
        
        # Check cookies
        if not matched and 'set-cookie' in headers_lower:
            cookies = headers_lower['set-cookie']
            for c_key, c_pattern in sig.cookies.items():
                if f"{c_key}=" in cookies.lower():
                    # Simplified cookie check
                    matched = True
                    # Version extraction from cookies is harder with this simple check, keeping basic for now.
                    break

        # Check HTML patterns
        if not matched and response.text:
            for pattern in sig.html_patterns:
                match = pattern.search(response.text)
                if match:
                    matched = True
                    if match.groups(): version = match.group(1)
                    break
                    
        # Check Meta tags
        if not matched:
            for m_key, m_pattern in sig.meta_tags.items():
                if m_key in meta_tags_extracted:
                    match = m_pattern.search(meta_tags_extracted[m_key])
                    if match:
                        matched = True
                        if match.groups(): version = match.group(1)
                        break

        if matched:
            matches.append(FingerprintMatch(category=sig.category, name=sig.name, version=version))

    return matches
