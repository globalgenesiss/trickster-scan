"""
trickster/database/repository.py
===========================
Camada de acesso a dados (Repository Pattern).

Fornece métodos assíncronos para todas as operações CRUD usando
SQLAlchemy 2.0 com suporte a SQLite e PostgreSQL.

Uso:
    async with get_repository() as repo:
        session_id = await repo.create_session(target_url="https://exemplo.com")
        await repo.save_request(request_model)
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import AsyncIterator, Dict, List, Optional

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from trickster.config import settings
from trickster.database.models import (
    AiAnalysisModel,
    Base,
    FindingModel,
    HttpRequestModel,
    HttpResponseModel,
    ScanSessionModel,
)
from trickster.utils.logger import get_logger
from trickster.utils.models import (
    AiAnalysis,
    Finding,
    HttpRequest,
    HttpResponse,
    ScanSession,
)

logger = get_logger(__name__)

# ── Engine e Session Factory ──────────────────────────────────────────────────

# Cria o engine assíncrono baseado na DATABASE_URL do .env
_engine = create_async_engine(
    settings.database_url,
    echo=False,  # True para debug de SQL
    future=True,
    # Pool size não se aplica ao SQLite
    **(
        {"pool_size": 5, "max_overflow": 10}
        if "postgresql" in settings.database_url
        else {}
    ),
)

# Factory de sessões assíncronas
_async_session = async_sessionmaker(
    bind=_engine,
    expire_on_commit=False,
    class_=AsyncSession,
)


async def init_database() -> None:
    """
    Cria todas as tabelas no banco de dados se não existirem.
    Deve ser chamado na inicialização da aplicação.
    """
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("database_initialized", url=settings.database_url)


@asynccontextmanager
async def get_repository() -> AsyncIterator["TricksterRepository"]:
    """
    Context manager que fornece um repositório com sessão gerenciada.
    
    Uso:
        async with get_repository() as repo:
            await repo.create_session(...)
    """
    async with _async_session() as session:
        yield TricksterRepository(session)


# ── Funções auxiliares de serialização ───────────────────────────────────────

def _serialize(data: object) -> Optional[str]:
    """Serializa dict/list para JSON string."""
    if data is None:
        return None
    return json.dumps(data, ensure_ascii=False, default=str)


def _deserialize(data: Optional[str]) -> object:
    """Deserializa JSON string para Python object."""
    if not data:
        return {}
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        return {}


# ── Repository ────────────────────────────────────────────────────────────────

class TricksterRepository:
    """
    Repositório central para todas as operações de banco de dados do Trickster.
    Encapsula SQLAlchemy e expõe uma API simples e tipada.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    # ── ScanSession ───────────────────────────────────────────────────────────

    async def create_session(
        self,
        session: ScanSession,
    ) -> str:
        """Persiste uma nova sessão de scan e retorna seu ID."""
        model = ScanSessionModel(
            id=session.id,
            target_url=session.target_url,
            status=session.status,
            ai_provider=session.ai_provider,
            ai_model=session.ai_model,
            started_at=session.started_at,
        )
        self._session.add(model)
        await self._session.commit()
        logger.info("session_created", session_id=session.id, target=session.target_url)
        return session.id

    async def update_session_status(
        self,
        session_id: str,
        status: str,
        finished_at: Optional[datetime] = None,
    ) -> None:
        """Atualiza o status de uma sessão."""
        values: Dict = {"status": status}
        if finished_at:
            values["finished_at"] = finished_at
        await self._session.execute(
            update(ScanSessionModel)
            .where(ScanSessionModel.id == session_id)
            .values(**values)
        )
        await self._session.commit()

    async def update_session_counters(self, session_id: str) -> None:
        """
        Recalcula e atualiza os contadores de uma sessão a partir dos dados
        reais no banco. Chamado ao final do scan.
        """
        # Conta requisições
        req_count = await self._session.scalar(
            select(func.count(HttpRequestModel.id)).where(
                HttpRequestModel.session_id == session_id
            )
        )

        # Conta respostas
        resp_count = await self._session.scalar(
            select(func.count(HttpResponseModel.id)).where(
                HttpResponseModel.session_id == session_id
            )
        )

        # Conta findings por severidade
        finding_rows = await self._session.execute(
            select(FindingModel.severity, func.count(FindingModel.id))
            .where(FindingModel.session_id == session_id)
            .group_by(FindingModel.severity)
        )
        severity_counts: Dict[str, int] = dict(finding_rows.all())

        await self._session.execute(
            update(ScanSessionModel)
            .where(ScanSessionModel.id == session_id)
            .values(
                total_requests=req_count or 0,
                total_responses=resp_count or 0,
                total_findings=sum(severity_counts.values()),
                critical_count=severity_counts.get("critical", 0),
                high_count=severity_counts.get("high", 0),
                medium_count=severity_counts.get("medium", 0),
                low_count=severity_counts.get("low", 0),
                info_count=severity_counts.get("informational", 0),
            )
        )
        await self._session.commit()

    async def get_session(self, session_id: str) -> Optional[ScanSessionModel]:
        """Retorna uma sessão pelo ID."""
        result = await self._session.execute(
            select(ScanSessionModel).where(ScanSessionModel.id == session_id)
        )
        return result.scalar_one_or_none()

    async def list_sessions(self, limit: int = 20) -> List[ScanSessionModel]:
        """Lista as sessões mais recentes."""
        result = await self._session.execute(
            select(ScanSessionModel)
            .order_by(ScanSessionModel.started_at.desc())
            .limit(limit)
        )
        return list(result.scalars().all())

    # ── HttpRequest ───────────────────────────────────────────────────────────

    async def save_request(self, request: HttpRequest) -> str:
        """Persiste uma requisição HTTP capturada."""
        model = HttpRequestModel(
            id=request.id,
            session_id=request.session_id,
            url=request.url,
            method=request.method,
            headers=_serialize(request.headers),
            query_params=_serialize(request.query_params),
            body=request.body,
            body_size=request.body_size,
            cookies=_serialize(request.cookies),
            jwt_tokens=_serialize(request.jwt_tokens),
            auth_tokens=_serialize(request.auth_tokens),
            content_type=request.content_type,
            is_https=request.is_https,
            timestamp=request.timestamp,
        )
        self._session.add(model)
        await self._session.commit()
        return request.id

    async def get_requests_for_session(
        self,
        session_id: str,
        limit: int = 1000,
    ) -> List[HttpRequestModel]:
        """Retorna todas as requisições de uma sessão."""
        result = await self._session.execute(
            select(HttpRequestModel)
            .where(HttpRequestModel.session_id == session_id)
            .order_by(HttpRequestModel.timestamp.asc())
            .limit(limit)
        )
        return list(result.scalars().all())

    async def get_unanalyzed_requests(
        self,
        session_id: str,
        batch_size: int = 10,
    ) -> List[HttpRequestModel]:
        """
        Retorna requisições que ainda não foram analisadas pela IA.
        Usado para processamento em lote.
        """
        # Subquery: IDs já referenciados em findings
        analyzed_subq = select(FindingModel.request_id).where(
            FindingModel.session_id == session_id,
            FindingModel.request_id.isnot(None),
        )

        result = await self._session.execute(
            select(HttpRequestModel)
            .where(
                HttpRequestModel.session_id == session_id,
                HttpRequestModel.id.notin_(analyzed_subq),
            )
            .order_by(HttpRequestModel.timestamp.asc())
            .limit(batch_size)
        )
        return list(result.scalars().all())

    # ── HttpResponse ──────────────────────────────────────────────────────────

    async def save_response(self, response: HttpResponse) -> str:
        """Persiste uma resposta HTTP capturada."""
        model = HttpResponseModel(
            id=response.id,
            request_id=response.request_id,
            session_id=response.session_id,
            status_code=response.status_code,
            headers=_serialize(response.headers),
            body=response.body,
            body_size=response.body_size,
            content_type=response.content_type,
            encoding=response.encoding,
            duration_ms=response.duration_ms,
            timestamp=response.timestamp,
        )
        self._session.add(model)
        await self._session.commit()
        return response.id

    async def get_response_for_request(
        self, request_id: str
    ) -> Optional[HttpResponseModel]:
        """Retorna a resposta de uma requisição."""
        result = await self._session.execute(
            select(HttpResponseModel).where(
                HttpResponseModel.request_id == request_id
            )
        )
        return result.scalar_one_or_none()

    # ── AiAnalysis ────────────────────────────────────────────────────────────

    async def save_analysis(self, analysis: AiAnalysis) -> str:
        """Persiste uma análise de IA com seus findings."""
        model = AiAnalysisModel(
            id=analysis.id,
            session_id=analysis.session_id,
            requests_analyzed=analysis.requests_analyzed,
            prompt_tokens=analysis.prompt_tokens,
            completion_tokens=analysis.completion_tokens,
            raw_response=analysis.raw_response,
            ai_provider=analysis.ai_provider,
            ai_model=analysis.ai_model,
            duration_ms=analysis.duration_ms,
            timestamp=analysis.timestamp,
        )
        self._session.add(model)
        await self._session.flush()  # Gera o ID sem commit

        # Salva os findings vinculados a esta análise
        for finding in analysis.findings:
            finding_model = FindingModel(
                id=finding.id,
                analysis_id=analysis.id,
                session_id=finding.session_id,
                request_id=finding.request_id,
                title=finding.title,
                description=finding.description,
                vulnerability_type=finding.vulnerability_type.value,
                severity=finding.severity.value,
                evidence=finding.evidence,
                affected_endpoint=finding.affected_endpoint,
                recommendation=finding.recommendation,
                references=_serialize(finding.references),
                false_positive_likelihood=finding.false_positive_likelihood,
                timestamp=finding.timestamp,
            )
            self._session.add(finding_model)

        await self._session.commit()
        logger.info(
            "analysis_saved",
            analysis_id=analysis.id,
            findings=len(analysis.findings),
        )
        return analysis.id

    async def get_findings_for_session(
        self,
        session_id: str,
    ) -> List[FindingModel]:
        """Retorna todos os findings de uma sessão, ordenados por severidade."""
        severity_order = {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
            "informational": 4,
        }

        result = await self._session.execute(
            select(FindingModel)
            .where(FindingModel.session_id == session_id)
            .order_by(FindingModel.timestamp.asc())
        )
        findings = list(result.scalars().all())
        # Ordena por severidade em Python (SQLite não suporta CASE nativamente)
        return sorted(
            findings,
            key=lambda f: severity_order.get(f.severity, 99),
        )

