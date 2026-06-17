"""trickster/analysis/ai_analyzer.py — Análise de segurança com Groq."""

from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from trickster.config import settings
from trickster.utils.logger import get_logger
from trickster.utils.models import AiAnalysis, Finding, Severity, VulnerabilityType
from trickster.utils.normalizer import build_request_summary

logger = get_logger(__name__)

_SYSTEM_PROMPT = """Você é um pentester sênior especializado em análise de tráfego HTTP.
Sua missão é encontrar TODAS as vulnerabilidades sem exceção.

REGRAS:
- Prefira falso positivo a falso negativo — reporte tudo que parecer suspeito
- Analise cada campo, header, cookie, parâmetro e response body
- Seja específico: cite o valor exato encontrado como evidência

CHECKLIST OBRIGATÓRIO — verifique cada item em TODA requisição:

[CREDENCIAIS E TOKENS]
- Senha (pw, password, pass, senha) em URL via GET → CRITICAL
- Token, API key, secret em URL → CRITICAL  
- JWT em cookie sem HttpOnly → HIGH
- Basic auth em header → HIGH
- Credenciais em body não criptografado → HIGH

[CONTROLE DE ACESSO]
- Parâmetro controlando privilégio (is_admin, is_author, role, admin, privileged, level) → CRITICAL
- ID numérico sequencial em URL (IDOR) → HIGH
- Acesso a recurso de outro usuário → HIGH
- Endpoint /admin, /console, /debug, /actuator exposto → HIGH

[INJEÇÃO]
- Input refletido em response sem sanitização (XSS) → HIGH
- Aspas simples/duplas em parâmetros aceitas → HIGH
- Erro de SQL em response → CRITICAL
- Path traversal (../) em parâmetros → HIGH
- Comando do sistema em parâmetros → CRITICAL

[CONFIGURAÇÃO]
- Header CSP ausente → MEDIUM
- Header X-Frame-Options ausente → MEDIUM
- Header HSTS ausente em HTTPS → MEDIUM
- Header X-Content-Type-Options ausente → LOW
- CORS Access-Control-Allow-Origin: * → MEDIUM
- Cookie sem Secure flag → MEDIUM
- Cookie sem HttpOnly flag → MEDIUM
- Cookie sem SameSite → LOW

[DADOS SENSÍVEIS]
- CPF, email, telefone, cartão em response → HIGH
- Stack trace ou erro interno em response → MEDIUM
- Versão de framework/servidor exposta → LOW
- Chave privada ou certificado em response → CRITICAL

[CSRF]
- Formulário POST sem token CSRF → HIGH
- Operação sensível via GET → HIGH

Responda APENAS com JSON neste formato:
{
  "findings": [
    {
      "title": "titulo descritivo curto",
      "description": "explicacao tecnica detalhada do problema e impacto",
      "vulnerability_type": "insecure_headers|exposed_token|auth_failure|authz_failure|idor|sensitive_data_exposure|info_leakage|admin_endpoint|cors_misconfiguration|xss|sql_injection|ssrf|path_traversal|csrf|other",
      "severity": "critical|high|medium|low|informational",
      "evidence": "valor/trecho EXATO do trafego que prova o problema",
      "affected_endpoint": "URL completa afetada",
      "recommendation": "como corrigir com referencias OWASP",
      "references": ["https://owasp.org/..."],
      "false_positive_likelihood": "low|medium|high"
    }
  ],
  "summary": "resumo executivo em 2-3 frases"
}

IMPORTANTE: {"findings": [], ...} so se realmente nao houver NADA suspeito.
JSON PURO, SEM MARKDOWN, SEM EXPLICACAO FORA DO JSON."""


def _build_analysis_prompt(summaries: List[str]) -> str:
    separator = "\n\n" + "═" * 60 + "\n\n"
    return f"""Analise as {len(summaries)} requisicoes abaixo aplicando o checklist completo.
Reporte CADA problema encontrado, mesmo que pareça menor.

{separator.join(summaries)}

Responda com o JSON de findings."""


class AiAnalyzer:

    def __init__(self) -> None:
        self._model = settings.groq_model
        self._client: Any = None
        self._initialize_client()

    def _initialize_client(self) -> None:
        try:
            from openai import AsyncOpenAI
            api_key = settings.groq_api_key
            if not api_key:
                logger.warning("groq_key_missing — configure GROQ_API_KEY no .env")
                return
            self._client = AsyncOpenAI(
                api_key=api_key,
                base_url="https://api.groq.com/openai/v1",
            )
            logger.info("ai_client_initialized", provider="groq", model=self._model)
        except ImportError:
            logger.error("openai_sdk_not_installed — rode: pip install openai")
            raise

    async def _call_groq(self, prompt: str) -> tuple[str, int, int]:
        response = await self._client.chat.completions.create(
            model=self._model,
            max_tokens=8000,
            temperature=0.1,  # Baixa temperatura = mais determinístico e preciso
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
        )
        text = response.choices[0].message.content or ""
        return text, response.usage.prompt_tokens, response.usage.completion_tokens

    def _parse_findings(self, raw: str, session_id: str, analysis_id: str) -> List[Finding]:
        findings: List[Finding] = []

        clean = raw.strip()
        # Remove markdown se presente
        if "```" in clean:
            import re
            clean = re.sub(r"```(?:json)?", "", clean).strip()

        try:
            data = json.loads(clean)
        except json.JSONDecodeError:
            # Tenta extrair JSON do meio do texto
            import re
            match = re.search(r'\{.*\}', clean, re.DOTALL)
            if match:
                try:
                    data = json.loads(match.group())
                except Exception:
                    logger.error("ai_response_unparseable", raw=raw[:300])
                    return []
            else:
                logger.error("ai_response_no_json", raw=raw[:300])
                return []

        logger.info("ai_findings_parsed", count=len(data.get("findings", [])))

        for item in data.get("findings", []):
            try:
                try:
                    vuln_type = VulnerabilityType(item.get("vulnerability_type", "other").lower())
                except ValueError:
                    vuln_type = VulnerabilityType.OTHER

                try:
                    severity = Severity(item.get("severity", "informational").lower())
                except ValueError:
                    severity = Severity.INFORMATIONAL

                findings.append(Finding(
                    id=str(uuid.uuid4()),
                    analysis_id=analysis_id,
                    session_id=session_id,
                    title=item.get("title", "Sem título"),
                    description=item.get("description", ""),
                    vulnerability_type=vuln_type,
                    severity=severity,
                    evidence=item.get("evidence", ""),
                    affected_endpoint=item.get("affected_endpoint", ""),
                    recommendation=item.get("recommendation", ""),
                    references=item.get("references", []),
                    false_positive_likelihood=item.get("false_positive_likelihood"),
                ))
            except Exception as exc:
                logger.warning("finding_parse_error", error=str(exc))

        return findings

    async def analyze_batch(self, session_id: str, traffic_pairs: List[Dict[str, Any]]) -> AiAnalysis:
        analysis_id = str(uuid.uuid4())
        start_time = time.monotonic()

        if not self._client:
            logger.error("ai_client_not_initialized")
            return AiAnalysis(id=analysis_id, session_id=session_id, ai_provider="groq", ai_model=self._model)

        summaries: List[str] = []
        for pair in traffic_pairs:
            req = pair.get("request")
            resp = pair.get("response")
            if not req:
                continue
            summaries.append(build_request_summary(
                url=req.url, method=req.method, headers=req.headers,
                query_params=req.query_params, body=req.body,
                cookies=req.cookies, jwt_tokens=req.jwt_tokens,
                auth_tokens=req.auth_tokens,
                response_status=resp.status_code if resp else None,
                response_headers=resp.headers if resp else None,
                response_body=resp.body if resp else None,
            ))

        if not summaries:
            return AiAnalysis(id=analysis_id, session_id=session_id, ai_provider="groq", ai_model=self._model)

        prompt = _build_analysis_prompt(summaries)
        logger.info("ai_analysis_starting", provider="groq", model=self._model, batch_size=len(summaries))

        try:
            raw_response, prompt_tokens, completion_tokens = await self._call_groq(prompt)
        except Exception as exc:
            logger.error("ai_api_error", error=str(exc))
            raise

        duration_ms = (time.monotonic() - start_time) * 1000
        findings = self._parse_findings(raw_response, session_id, analysis_id)

        logger.info(
            "ai_analysis_completed",
            findings=len(findings),
            tokens=prompt_tokens + completion_tokens,
            duration_ms=f"{duration_ms:.0f}ms",
        )

        return AiAnalysis(
            id=analysis_id, session_id=session_id,
            requests_analyzed=len(summaries),
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            findings=findings,
            raw_response=raw_response,
            ai_provider="groq",
            ai_model=self._model,
            timestamp=datetime.now(timezone.utc),
            duration_ms=duration_ms,
        )