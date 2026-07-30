import asyncio
import json
import socket
from typing import Dict, List, Optional
from urllib.parse import urlparse

import httpx

DEFAULT_WORDLIST = [
    ".env",
    ".git/config",
    "admin/",
    "backup.zip",
    "server-status",
    "wp-config.php.bak",
    "api/v1/",
    "swagger-ui.html",
    "robots.txt"
]

async def fuzz_directory(client: httpx.AsyncClient, base_url: str, wordlist: Optional[List[str]] = None) -> Dict[str, int]:
    """
    Fuzzes the target URL for hidden paths using a wordlist.
    Returns a dictionary of path -> status_code for non-404 responses.
    """
    if not wordlist:
        wordlist = DEFAULT_WORDLIST

    results = {}
    base_url = base_url.rstrip("/")

    async def check_path(path: str):
        url = f"{base_url}/{path.lstrip('/')}"
        try:
            # Quick HEAD request to see if it exists
            response = await client.head(url, follow_redirects=False)
            if response.status_code != 404:
                results[path] = response.status_code
        except Exception:
            pass

    # Basic concurrency control for fuzzing
    sem = asyncio.Semaphore(20)
    
    async def bounded_check(path):
        async with sem:
            await check_path(path)

    tasks = [bounded_check(path) for path in wordlist]
    await asyncio.gather(*tasks)
    
    return results

async def scan_ports(host: str, ports: List[int]) -> List[int]:
    """
    Performs a fast TCP connect scan on the specified ports.
    """
    open_ports = []
    
    async def check_port(port: int):
        try:
            # Set a very short timeout for port scanning
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=1.0)
            writer.close()
            await writer.wait_closed()
            open_ports.append(port)
        except Exception:
            pass

    tasks = [check_port(p) for p in ports]
    await asyncio.gather(*tasks)
    return sorted(open_ports)

async def enumerate_subdomains_crtsh(domain: str) -> List[str]:
    """
    Queries crt.sh (Certificate Transparency Logs) to find subdomains.
    """
    subdomains = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get("name_value", "")
                    # crt.sh can return multiple domains separated by newlines
                    for name in name_value.splitlines():
                        name = name.strip().lower()
                        if name.endswith(domain) and not name.startswith("*"):
                            subdomains.add(name)
    except Exception:
        pass

    return sorted(list(subdomains))
