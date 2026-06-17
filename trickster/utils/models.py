"""trickster/utils/models.py — Modelos de domínio."""

from __future__ import annotations
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    CRITICAL      = "critical"
    HIGH          = "high"
    MEDIUM        = "medium"
    LOW           = "low"
    INFORMATIONAL = "informational"


class VulnerabilityType(str, Enum):
    INSECURE_HEADERS        = "insecure_headers"
    EXPOSED_TOKEN           = "exposed_token"
    AUTH_FAILURE            = "auth_failure"
    AUTHZ_FAILURE           = "authz_failure"
    IDOR                    = "idor"
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"
    INFO_LEAKAGE            = "info_leakage"
    ADMIN_ENDPOINT          = "admin_endpoint"
    CORS_MISCONFIGURATION   = "cors_misconfiguration"
    XSS                     = "xss"
    SQL_INJECTION           = "sql_injection"
    SSRF                    = "ssrf"
    PATH_TRAVERSAL          = "path_traversal"
    CSRF                    = "csrf"
    OTHER                   = "other"


class HttpRequest(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str
    url: str
    method: str
    headers: Dict[str, str] = Field(default_factory=dict)
    query_params: Dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None
    body_size: int = 0
    cookies: Dict[str, str] = Field(default_factory=dict)
    jwt_tokens: List[str] = Field(default_factory=list)
    auth_tokens: List[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    content_type: Optional[str] = None
    is_https: bool = False

    @field_validator("method")
    @classmethod
    def normalize_method(cls, v: str) -> str:
        return v.upper()

    @property
    def domain(self) -> str:
        from urllib.parse import urlparse
        return urlparse(self.url).netloc

    @property
    def path(self) -> str:
        from urllib.parse import urlparse
        return urlparse(self.url).path


class HttpResponse(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    request_id: str
    session_id: str
    status_code: int
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None
    body_size: int = 0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    content_type: Optional[str] = None
    encoding: Optional[str] = None
    duration_ms: Optional[float] = None

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300

    @property
    def is_error(self) -> bool:
        return self.status_code >= 400


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    analysis_id: str
    request_id: Optional[str] = None
    session_id: str
    title: str
    description: str
    vulnerability_type: VulnerabilityType = VulnerabilityType.OTHER
    severity: Severity
    evidence: str
    affected_endpoint: str
    recommendation: str
    references: List[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    false_positive_likelihood: Optional[str] = None


class AiAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str
    requests_analyzed: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    findings: List[Finding] = Field(default_factory=list)
    raw_response: Optional[str] = None
    ai_provider: str
    ai_model: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    duration_ms: Optional[float] = None


class ScanSession(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target_url: str
    total_requests: int = 0
    total_responses: int = 0
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    ai_provider: Optional[str] = None
    ai_model: Optional[str] = None
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: Optional[datetime] = None
    status: str = "running"

    @property
    def duration_seconds(self) -> Optional[float]:
        if self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None
