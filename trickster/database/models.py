"""trickster/database/models.py — Modelos ORM SQLAlchemy."""

from __future__ import annotations
from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class ScanSessionModel(Base):
    __tablename__ = "scan_sessions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    target_url: Mapped[str] = mapped_column(String(2048))
    status: Mapped[str] = mapped_column(String(20), default="running")
    total_requests: Mapped[int] = mapped_column(Integer, default=0)
    total_responses: Mapped[int] = mapped_column(Integer, default=0)
    total_findings: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)
    info_count: Mapped[int] = mapped_column(Integer, default=0)
    ai_provider: Mapped[Optional[str]] = mapped_column(String(50))
    ai_model: Mapped[Optional[str]] = mapped_column(String(100))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    requests: Mapped[List["HttpRequestModel"]] = relationship(back_populates="session", cascade="all, delete-orphan")
    analyses: Mapped[List["AiAnalysisModel"]] = relationship(back_populates="session", cascade="all, delete-orphan")


class HttpRequestModel(Base):
    __tablename__ = "http_requests"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    session_id: Mapped[str] = mapped_column(String(36), ForeignKey("scan_sessions.id", ondelete="CASCADE"), index=True)
    url: Mapped[str] = mapped_column(String(4096))
    method: Mapped[str] = mapped_column(String(10))
    headers: Mapped[Optional[str]] = mapped_column(Text)
    query_params: Mapped[Optional[str]] = mapped_column(Text)
    body: Mapped[Optional[str]] = mapped_column(Text)
    body_size: Mapped[int] = mapped_column(Integer, default=0)
    cookies: Mapped[Optional[str]] = mapped_column(Text)
    jwt_tokens: Mapped[Optional[str]] = mapped_column(Text)
    auth_tokens: Mapped[Optional[str]] = mapped_column(Text)
    content_type: Mapped[Optional[str]] = mapped_column(String(256))
    is_https: Mapped[bool] = mapped_column(Boolean, default=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    session: Mapped["ScanSessionModel"] = relationship(back_populates="requests")
    response: Mapped[Optional["HttpResponseModel"]] = relationship(back_populates="request", uselist=False, cascade="all, delete-orphan")


class HttpResponseModel(Base):
    __tablename__ = "http_responses"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    request_id: Mapped[str] = mapped_column(String(36), ForeignKey("http_requests.id", ondelete="CASCADE"), unique=True)
    session_id: Mapped[str] = mapped_column(String(36), index=True)
    status_code: Mapped[int] = mapped_column(Integer)
    headers: Mapped[Optional[str]] = mapped_column(Text)
    body: Mapped[Optional[str]] = mapped_column(Text)
    body_size: Mapped[int] = mapped_column(Integer, default=0)
    content_type: Mapped[Optional[str]] = mapped_column(String(256))
    encoding: Mapped[Optional[str]] = mapped_column(String(50))
    duration_ms: Mapped[Optional[float]] = mapped_column(Float)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    request: Mapped["HttpRequestModel"] = relationship(back_populates="response")


class AiAnalysisModel(Base):
    __tablename__ = "ai_analyses"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    session_id: Mapped[str] = mapped_column(String(36), ForeignKey("scan_sessions.id", ondelete="CASCADE"), index=True)
    requests_analyzed: Mapped[int] = mapped_column(Integer, default=0)
    prompt_tokens: Mapped[int] = mapped_column(Integer, default=0)
    completion_tokens: Mapped[int] = mapped_column(Integer, default=0)
    raw_response: Mapped[Optional[str]] = mapped_column(Text)
    ai_provider: Mapped[str] = mapped_column(String(50))
    ai_model: Mapped[str] = mapped_column(String(100))
    duration_ms: Mapped[Optional[float]] = mapped_column(Float)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    session: Mapped["ScanSessionModel"] = relationship(back_populates="analyses")
    findings: Mapped[List["FindingModel"]] = relationship(back_populates="analysis", cascade="all, delete-orphan")


class FindingModel(Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    analysis_id: Mapped[str] = mapped_column(String(36), ForeignKey("ai_analyses.id", ondelete="CASCADE"), index=True)
    session_id: Mapped[str] = mapped_column(String(36), index=True)
    request_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str] = mapped_column(Text)
    vulnerability_type: Mapped[str] = mapped_column(String(100))
    severity: Mapped[str] = mapped_column(String(20), index=True)
    evidence: Mapped[str] = mapped_column(Text)
    affected_endpoint: Mapped[str] = mapped_column(String(4096))
    recommendation: Mapped[str] = mapped_column(Text)
    references: Mapped[Optional[str]] = mapped_column(Text)
    false_positive_likelihood: Mapped[Optional[str]] = mapped_column(String(50))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    analysis: Mapped["AiAnalysisModel"] = relationship(back_populates="findings")