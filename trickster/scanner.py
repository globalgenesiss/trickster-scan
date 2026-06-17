"""
trickster/scanner.py
===============
Orquestrador central do Trickster.

Coordena o pipeline completo de análise:
    1. Inicializa banco de dados e sessão
    2. Captura tráfego com Playwright (CDP)
    3. Salva requisições e respostas no banco
    4. Processa em lotes pela IA
    5. Salva findings
    6. Atualiza contadores da sessão
    7. Gera relatórios

O Scanner é o único ponto de entrada para análise e é chamado
diretamente pela CLI.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import List, Optional

from trickster.analysis.ai_analyzer import AiAnalyzer
from trickster.capture.playwright_capture import PlaywrightCapture
from trickster.config import settings
from trickster.database.repository import get_repository, init_database
from trickster.reports.generator import ReportGenerator
from trickster.utils.logger import get_logger
from trickster.utils.models import AiAnalysis, HttpRequest, HttpResponse, ScanSession

logger = get_logger(__name__)


class Scanner:
    """
    Pipeline completo de análise de segurança passiva.
    
    Uso:
        scanner = Scanner()
        session_id = await scanner.run(url="https://exemplo.com")
    """

    def __init__(self) -> None:
        self._analyzer = AiAnalyzer()
        self._reporter = ReportGenerator()

    async def run(self, url: str) -> str:
        """
        Executa o pipeline completo de análise para uma URL.
        
        Args:
            url: URL alvo para análise
            
        Returns:
            ID da sessão criada
        """
        # ── 1. Inicializa banco de dados ───────────────────────────────────────
        await init_database()

        # ── 2. Cria sessão de scan ─────────────────────────────────────────────
        session = ScanSession(
            target_url=url,
            ai_provider=settings.ai_provider.value,
            ai_model=settings.get_ai_model(),
        )

        async with get_repository() as repo:
            await repo.create_session(session)

        logger.info("scan_started", session_id=session.id, url=url)

        # Buffers em memória para processamento em lote
        captured_pairs: List[dict] = []

        try:
            # ── 3. Captura tráfego ─────────────────────────────────────────────
            async with PlaywrightCapture() as capture:
                pairs = await capture.capture(
                    url=url,
                    session_id=session.id,
                )

            # ── 4. Persiste requisições e respostas ────────────────────────────
            logger.info("saving_traffic", count=len(pairs))

            async with get_repository() as repo:
                seen_ids = set()
                for req, resp in pairs:
                    if req.id in seen_ids:
                        continue
                    seen_ids.add(req.id)
                    await repo.save_request(req)
                    await repo.save_response(resp)
                    captured_pairs.append({"request": req, "response": resp})

            # ── 5. Análise por IA em lotes ─────────────────────────────────────
            batch_size = settings.ai_batch_size
            total_batches = (len(captured_pairs) + batch_size - 1) // batch_size

            logger.info(
                "ai_analysis_starting",
                total_pairs=len(captured_pairs),
                batches=total_batches,
            )

            for batch_idx in range(0, len(captured_pairs), batch_size):
                batch = captured_pairs[batch_idx: batch_idx + batch_size]
                batch_num = (batch_idx // batch_size) + 1

                logger.info(
                    "processing_batch",
                    batch=f"{batch_num}/{total_batches}",
                    size=len(batch),
                )

                try:
                    analysis: AiAnalysis = await self._analyzer.analyze_batch(
                        session_id=session.id,
                        traffic_pairs=batch,
                    )

                    # Salva análise e findings
                    async with get_repository() as repo:
                        await repo.save_analysis(analysis)

                    logger.info(
                        "batch_completed",
                        batch=f"{batch_num}/{total_batches}",
                        findings=len(analysis.findings),
                    )

                except Exception as exc:
                    logger.error(
                        "batch_analysis_error",
                        batch=batch_num,
                        error=str(exc),
                    )
                    # Continua com o próximo lote mesmo se um falhar

                # Pequena pausa para não sobrecarregar a API de IA
                if batch_idx + batch_size < len(captured_pairs):
                    await asyncio.sleep(0.5)

            # ── 6. Atualiza contadores da sessão ───────────────────────────────
            async with get_repository() as repo:
                await repo.update_session_counters(session.id)
                await repo.update_session_status(
                    session_id=session.id,
                    status="completed",
                    finished_at=datetime.now(timezone.utc),
                )

            # ── 7. Gera relatórios ─────────────────────────────────────────────
            await self._generate_reports(session.id)

            logger.info("scan_completed", session_id=session.id)

        except Exception as exc:
            logger.error("scan_failed", session_id=session.id, error=str(exc))

            async with get_repository() as repo:
                await repo.update_session_status(
                    session_id=session.id,
                    status="failed",
                    finished_at=datetime.now(timezone.utc),
                )
            raise

        return session.id

    async def _generate_reports(self, session_id: str) -> None:
        """Recupera dados do banco e gera os relatórios."""
        async with get_repository() as repo:
            session_model = await repo.get_session(session_id)
            findings = await repo.get_findings_for_session(session_id)

        if not session_model:
            logger.warning("session_not_found_for_report", session_id=session_id)
            return

        generated = self._reporter.generate(session_model, findings)

        for fmt, path in generated.items():
            logger.info("report_generated", format=fmt, path=str(path))

