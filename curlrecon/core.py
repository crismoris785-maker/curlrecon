import asyncio
from time import perf_counter
from typing import Dict, List, Optional

import httpx

from curlrecon.models import RequestData, ResponseData, TargetResult
from curlrecon.security import evaluate_security_headers
from curlrecon.signatures import analyze_response


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
    ):
        self.method = method.upper()
        self.headers = headers or {}
        if "user-agent" not in {k.lower() for k in self.headers}:
            self.headers["User-Agent"] = user_agent
        self.proxy = proxy
        self.verify = not insecure
        self.data = data
        self.location = location
        self.timeout = timeout
        self.threads = threads

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
