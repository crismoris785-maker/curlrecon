from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class FingerprintMatch(BaseModel):
    category: str
    name: str
    version: Optional[str] = None
    confidence: float = 1.0


class HeaderStatus(BaseModel):
    present: bool
    value: Optional[str] = None
    description: str


class SecurityBaseline(BaseModel):
    headers: Dict[str, HeaderStatus] = Field(default_factory=dict)

    @property
    def score(self) -> int:
        if not self.headers:
            return 0
        present_count = sum(1 for h in self.headers.values() if h.present)
        return int((present_count / len(self.headers)) * 100)


class RequestData(BaseModel):
    method: str
    url: str
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None


class ResponseData(BaseModel):
    status_code: int
    headers: Dict[str, str] = Field(default_factory=dict)
    content_length: int
    content_type: str
    text: str = ""
    redirect_history: List[str] = Field(default_factory=dict)
    elapsed_seconds: float = 0.0


class TargetResult(BaseModel):
    url: str
    success: bool
    error: Optional[str] = None
    request: Optional[RequestData] = None
    response: Optional[ResponseData] = None
    fingerprints: List[FingerprintMatch] = Field(default_factory=list)
    security: Optional[SecurityBaseline] = None
    fuzz_results: Dict[str, int] = Field(default_factory=dict)
    secrets_found: List[str] = Field(default_factory=list)
    open_ports: List[int] = Field(default_factory=list)
    subdomains: List[str] = Field(default_factory=list)
    vulnerabilities: List[str] = Field(default_factory=list)


class ScanReport(BaseModel):
    targets: List[TargetResult] = Field(default_factory=list)
    total_scanned: int = 0
    successful: int = 0
    failed: int = 0
    scan_duration: float = 0.0
