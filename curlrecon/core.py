import asyncio
from time import perf_counter
from typing import Dict, List, Optional

import httpx

from urllib.parse import urlparse

from curlrecon.models import RequestData, ResponseData, TargetResult
from curlrecon.security import evaluate_security_headers
from curlrecon.signatures import analyze_response
from curlrecon.secrets import extract_secrets
from curlrecon.active import fuzz_directory, scan_ports, enumerate_subdomains_crtsh
from curlrecon.active import fuzz_directory, scan_ports, enumerate_subdomains_crtsh
from curlrecon.vuln import check_cors, check_subdomain_takeover, check_cves
from curlrecon.evasion import get_random_user_agent, get_spoofed_headers


class ReconEngine:
    def __init__(
        self,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        user_agent: str = "CurlRecon/1.1",
        proxy: Optional[str] = None,
        insecure: bool = False,
        data: Optional[str] = None,
        location: bool = True,
        timeout: float = 10.0,
        threads: int = 10,
        fuzz: bool = False,
        wordlist: Optional[List[str]] = None,
        ports: bool = False,
        subdomains: bool = False,
        vuln: bool = False,
        evade: bool = False,
    ):
        self.method = method.upper()
        self.headers = headers or {}
        
        self.evade = evade
        if self.evade:
            self.headers.update(get_spoofed_headers("127.0.0.1"))
            self.headers["User-Agent"] = get_random_user_agent()
            
        if "user-agent" not in {k.lower() for k in self.headers}:
            self.headers["User-Agent"] = user_agent
        self.proxy = proxy
        self.verify = not insecure
        self.data = data
        self.location = location
        self.timeout = timeout
        self.threads = threads
        self.fuzz = fuzz
        self.wordlist = wordlist
        self.ports = ports
        self.subdomains = subdomains
        self.vuln = vuln

    async def _scan_target(self, client: httpx.AsyncClient, url: str) -> TargetResult:
        if not url.startswith("http"):
            url = f"http://{url}"

        req_data = RequestData(
            method=self.method, url=url, headers=self.headers, body=self.data
        )

        result = TargetResult(url=url, success=False, request=req_data)

        try:
            start_time = perf_counter()
            response = await client.request(
                method=self.method,
                url=url,
                headers=self.headers,
                content=self.data,
                follow_redirects=self.location,
            )
            elapsed = perf_counter() - start_time

            resp_headers = dict(response.headers)
            resp_data = ResponseData(
                status_code=response.status_code,
                headers=resp_headers,
                content_length=len(response.content),
                content_type=resp_headers.get("content-type", ""),
                text=response.text,
                redirect_history=[str(r.url) for r in response.history],
                elapsed_seconds=elapsed,
            )

            result.response = resp_data
            result.success = True

            # Analyze
            result.fingerprints = analyze_response(resp_data)
            result.security = evaluate_security_headers(resp_headers)
            
            if self.vuln:
                # 1. CORS
                cors_vuln = await check_cors(client, url)
                if cors_vuln:
                    result.vulnerabilities.append(cors_vuln)
                
                # 2. Subdomain Takeover
                takeover_vuln = check_subdomain_takeover(resp_data.text, resp_data.status_code)
                if takeover_vuln:
                    result.vulnerabilities.append(takeover_vuln)
                
                # 3. CVE Mapping
                cve_vulns = check_cves(result.fingerprints)
                result.vulnerabilities.extend(cve_vulns)
            
            # Active Scans
            # 1. Secrets
            result.secrets_found = extract_secrets(resp_data.text)
            
            # 2. Fuzzing
            if self.fuzz:
                result.fuzz_results = await fuzz_directory(client, url, self.wordlist)
            
            # 3. Subdomains
            if self.subdomains:
                parsed_url = urlparse(url)
                domain = parsed_url.netloc.split(':')[0]
                result.subdomains = await enumerate_subdomains_crtsh(domain)
                
            # 4. Port Scanning
            if self.ports:
                parsed_url = urlparse(url)
                host = parsed_url.netloc.split(':')[0]
                common_ports = [80, 443, 8080, 8443, 22, 3306, 5432, 21, 23, 25]
                result.open_ports = await scan_ports(host, common_ports)

        except Exception as e:
            result.error = str(e)

        return result

    async def run(self, targets: List[str]) -> List[TargetResult]:
        transport = httpx.AsyncHTTPTransport(verify=self.verify)
        if self.proxy:
            # Assuming standard HTTP/HTTPS proxy for simplicity in this basic setup
            transport = httpx.AsyncHTTPProxyTransport(
                proxy_url=self.proxy, verify=self.verify
            )

        limits = httpx.Limits(
            max_connections=self.threads, max_keepalive_connections=self.threads
        )

        async with httpx.AsyncClient(
            transport=transport, timeout=self.timeout, limits=limits, http2=True
        ) as client:

            # Semaphore to limit concurrency strictly
            sem = asyncio.Semaphore(self.threads)

            async def bounded_scan(target):
                async with sem:
                    return await self._scan_target(client, target)

            tasks = [bounded_scan(t) for t in targets]
            results = await asyncio.gather(*tasks)
            return results
