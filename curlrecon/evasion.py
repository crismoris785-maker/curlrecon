import random

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/116.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36 Edg/115.0.1901.188"
]

def get_random_user_agent() -> str:
    """Returns a random modern User-Agent string."""
    return random.choice(USER_AGENTS)

def get_spoofed_headers(ip_address: str = "127.0.0.1") -> dict:
    """
    Returns a dictionary of headers commonly used to spoof the origin IP address.
    Many basic WAFs will trust these headers and assume the request is internal.
    """
    return {
        "X-Forwarded-For": ip_address,
        "X-Real-IP": ip_address,
        "X-Client-IP": ip_address,
        "True-Client-IP": ip_address,
        "X-Originating-IP": ip_address,
        "X-Remote-IP": ip_address,
        "X-Remote-Addr": ip_address
    }
