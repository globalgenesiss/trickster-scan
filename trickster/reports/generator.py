"""
trickster/reports/generator.py
==========================
Gerador de relatórios de segurança em múltiplos formatos.

Formatos suportados:
- JSON  : estrutura completa, ideal para integração com outras ferramentas
- HTML  : relatório visual com cores por severidade, pronto para compartilhar
- Markdown : compatível com GitHub, GitLab, Notion, Obsidian

Cada finding contém:
    - Título
    - Descrição técnica
    - Evidência do tráfego
    - Endpoint afetado
    - Nível de severidade (com badge colorido no HTML)
    - Recomendação de correção
    - Referências (OWASP, CWE, CVE)
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from trickster.config import settings
from trickster.database.models import FindingModel, ScanSessionModel
from trickster.utils.logger import get_logger

logger = get_logger(__name__)

# ── Mapeamento de cores por severidade ────────────────────────────────────────

_SEVERITY_COLORS: Dict[str, str] = {
    "critical":      "#dc2626",   # red-600
    "high":          "#ea580c",   # orange-600
    "medium":        "#d97706",   # amber-600
    "low":           "#2563eb",   # blue-600
    "informational": "#6b7280",   # gray-500
}

_SEVERITY_BADGES: Dict[str, str] = {
    "critical":      "🔴 CRITICAL",
    "high":          "🟠 HIGH",
    "medium":        "🟡 MEDIUM",
    "low":           "🔵 LOW",
    "informational": "⚪ INFO",
}

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]


# ── HTML Template ─────────────────────────────────────────────────────────────

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Trickster Security Report — {target}</title>
<style>
  :root {{
    --bg: #0f172a; --surface: #1e293b; --border: #334155;
    --text: #f1f5f9; --muted: #94a3b8;
    --critical: #dc2626; --high: #ea580c;
    --medium: #d97706; --low: #2563eb; --info: #6b7280;
    --code-bg: #0f172a;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; padding: 2rem; }}
  .header {{ border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; }}
  .header h1 {{ font-size: 1.75rem; font-weight: 700; color: #38bdf8; }}
  .header .meta {{ color: var(--muted); font-size: 0.875rem; margin-top: 0.5rem; }}
  .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
  .stat-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; text-align: center; }}
  .stat-card .count {{ font-size: 2rem; font-weight: 700; }}
  .stat-card .label {{ font-size: 0.75rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; margin-top: 0.25rem; }}
  .stat-card.critical .count {{ color: var(--critical); }}
  .stat-card.high .count {{ color: var(--high); }}
  .stat-card.medium .count {{ color: var(--medium); }}
  .stat-card.low .count {{ color: var(--low); }}
  .stat-card.info .count {{ color: var(--info); }}
  .finding {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; margin-bottom: 1rem; border-left: 4px solid var(--border); }}
  .finding.critical {{ border-left-color: var(--critical); }}
  .finding.high {{ border-left-color: var(--high); }}
  .finding.medium {{ border-left-color: var(--medium); }}
  .finding.low {{ border-left-color: var(--low); }}
  .finding.informational {{ border-left-color: var(--info); }}
  .finding-header {{ display: flex; justify-content: space-between; align-items: flex-start; gap: 1rem; margin-bottom: 1rem; }}
  .finding-title {{ font-size: 1.1rem; font-weight: 600; }}
  .badge {{ font-size: 0.75rem; font-weight: 700; padding: 0.25rem 0.75rem; border-radius: 999px; white-space: nowrap; }}
  .badge.critical {{ background: #450a0a; color: var(--critical); }}
  .badge.high {{ background: #431407; color: var(--high); }}
  .badge.medium {{ background: #451a03; color: var(--medium); }}
  .badge.low {{ background: #172554; color: var(--low); }}
  .badge.informational {{ background: #1c1917; color: var(--info); }}
  .field-label {{ font-size: 0.75rem; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.375rem; margin-top: 1rem; }}
  .field-value {{ color: var(--text); line-height: 1.6; }}
  .endpoint {{ font-family: 'Cascadia Code', 'Consolas', monospace; font-size: 0.875rem; color: #38bdf8; word-break: break-all; }}
  .evidence {{ background: var(--code-bg); border: 1px solid var(--border); border-radius: 6px; padding: 1rem; font-family: 'Cascadia Code', 'Consolas', monospace; font-size: 0.8rem; white-space: pre-wrap; word-break: break-all; color: #7dd3fc; overflow-x: auto; max-height: 300px; overflow-y: auto; }}
  .refs a {{ color: #38bdf8; text-decoration: none; display: block; font-size: 0.875rem; }}
  .refs a:hover {{ text-decoration: underline; }}
  .section-title {{ font-size: 1.25rem; font-weight: 700; margin-bottom: 1rem; color: var(--text); }}
  .no-findings {{ text-align: center; padding: 3rem; color: var(--muted); }}
  footer {{ margin-top: 3rem; text-align: center; color: var(--muted); font-size: 0.75rem; border-top: 1px solid var(--border); padding-top: 1rem; }}
</style>
</head>
<body>
<div class="header">
  <h1>🦅 Trickster Security Report</h1>
  <div class="meta">
    <strong>Target:</strong> {target} &nbsp;|&nbsp;
    <strong>Session:</strong> {session_id} &nbsp;|&nbsp;
    <strong>Date:</strong> {date} &nbsp;|&nbsp;
    <strong>Model:</strong> {model}
  </div>
</div>

<div class="stats">
  <div class="stat-card">
    <div class="count" style="color: #38bdf8">{total_requests}</div>
    <div class="label">Requests</div>
  </div>
  <div class="stat-card">
    <div class="count" style="color: #38bdf8">{total_findings}</div>
    <div class="label">Findings</div>
  </div>
  <div class="stat-card critical">
    <div class="count">{critical}</div>
    <div class="label">Critical</div>
  </div>
  <div class="stat-card high">
    <div class="count">{high}</div>
    <div class="label">High</div>
  </div>
  <div class="stat-card medium">
    <div class="count">{medium}</div>
    <div class="label">Medium</div>
  </div>
  <div class="stat-card low">
    <div class="count">{low}</div>
    <div class="label">Low</div>
  </div>
  <div class="stat-card info">
    <div class="count">{info}</div>
    <div class="label">Info</div>
  </div>
</div>

<div class="section-title">Findings</div>
{findings_html}

<footer>Generated by Trickster v1.0.0 — Passive HTTP Analysis &amp; Vulnerability Scanner</footer>
</body>
</html>"""

_FINDING_HTML = """<div class="finding {severity}">
  <div class="finding-header">
    <div class="finding-title">{title}</div>
    <span class="badge {severity}">{badge}</span>
  </div>
  <div class="field-label">Description</div>
  <div class="field-value">{description}</div>
  <div class="field-label">Affected Endpoint</div>
  <div class="endpoint">{endpoint}</div>
  <div class="field-label">Evidence</div>
  <div class="evidence">{evidence}</div>
  <div class="field-label">Recommendation</div>
  <div class="field-value">{recommendation}</div>
  {refs_html}
</div>"""


# ── Report Generator ──────────────────────────────────────────────────────────

class ReportGenerator:
    """
    Gera relatórios de segurança nos formatos JSON, HTML e Markdown.
    
    Uso:
        gen = ReportGenerator()
        paths = await gen.generate(session, findings)
    """

    def __init__(self) -> None:
        self._output_dir = settings.output_dir
        self._formats = settings.report_formats

    def _findings_to_dict(self, findings: List[FindingModel]) -> List[Dict[str, Any]]:
        """Converte FindingModel para dicionário serializável."""
        result = []
        for f in findings:
            refs = []
            try:
                refs = json.loads(f.references or "[]")
            except Exception:
                pass

            result.append({
                "id": f.id,
                "title": f.title,
                "description": f.description,
                "vulnerability_type": f.vulnerability_type,
                "severity": f.severity,
                "evidence": f.evidence,
                "affected_endpoint": f.affected_endpoint,
                "recommendation": f.recommendation,
                "references": refs,
                "false_positive_likelihood": f.false_positive_likelihood,
                "timestamp": f.timestamp.isoformat() if f.timestamp else None,
            })
        return result

    def generate_json(
        self,
        session: ScanSessionModel,
        findings: List[FindingModel],
        output_path: Path,
    ) -> Path:
        """Gera relatório em JSON estruturado."""
        data = {
            "trickster_version": "1.0.0",
            "report_generated_at": datetime.now(timezone.utc).isoformat(),
            "session": {
                "id": session.id,
                "target_url": session.target_url,
                "started_at": session.started_at.isoformat() if session.started_at else None,
                "finished_at": session.finished_at.isoformat() if session.finished_at else None,
                "status": session.status,
                "ai_provider": session.ai_provider,
                "ai_model": session.ai_model,
                "total_requests": session.total_requests,
                "total_findings": session.total_findings,
                "severity_summary": {
                    "critical": session.critical_count,
                    "high": session.high_count,
                    "medium": session.medium_count,
                    "low": session.low_count,
                    "informational": session.info_count,
                },
            },
            "findings": self._findings_to_dict(findings),
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        logger.info("report_json_generated", path=str(output_path))
        return output_path

    def generate_html(
        self,
        session: ScanSessionModel,
        findings: List[FindingModel],
        output_path: Path,
    ) -> Path:
        """Gera relatório HTML com design escuro e badges coloridos."""
        # Ordena findings por severidade
        sorted_findings = sorted(
            findings,
            key=lambda f: _SEVERITY_ORDER.index(f.severity)
            if f.severity in _SEVERITY_ORDER else 99,
        )

        # Gera HTML para cada finding
        findings_html_parts: List[str] = []
        for f in sorted_findings:
            refs = []
            try:
                refs = json.loads(f.references or "[]")
            except Exception:
                pass

            refs_html = ""
            if refs:
                refs_items = "\n".join(
                    f'    <a href="{r}" target="_blank" rel="noopener">{r}</a>'
                    for r in refs
                )
                refs_html = f'<div class="field-label">References</div><div class="refs">{refs_items}</div>'

            finding_html = _FINDING_HTML.format(
                severity=f.severity,
                title=_escape_html(f.title),
                badge=_SEVERITY_BADGES.get(f.severity, f.severity.upper()),
                description=_escape_html(f.description),
                endpoint=_escape_html(f.affected_endpoint),
                evidence=_escape_html(f.evidence[:1000]),
                recommendation=_escape_html(f.recommendation),
                refs_html=refs_html,
            )
            findings_html_parts.append(finding_html)

        findings_html = (
            "\n".join(findings_html_parts)
            if findings_html_parts
            else '<div class="no-findings">✅ Nenhum finding identificado</div>'
        )

        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        html = _HTML_TEMPLATE.format(
            target=_escape_html(session.target_url),
            session_id=session.id,
            date=date_str,
            model=session.ai_model or "N/A",
            total_requests=session.total_requests,
            total_findings=session.total_findings,
            critical=session.critical_count,
            high=session.high_count,
            medium=session.medium_count,
            low=session.low_count,
            info=session.info_count,
            findings_html=findings_html,
        )

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

        logger.info("report_html_generated", path=str(output_path))
        return output_path

    def generate_markdown(
        self,
        session: ScanSessionModel,
        findings: List[FindingModel],
        output_path: Path,
    ) -> Path:
        """Gera relatório em Markdown (GitHub-flavored)."""
        lines: List[str] = []

        # Cabeçalho
        lines += [
            "# 🦅 Trickster Security Report",
            "",
            f"**Target:** {session.target_url}  ",
            f"**Session ID:** `{session.id}`  ",
            f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  ",
            f"**AI Model:** {session.ai_model or 'N/A'}  ",
            f"**Status:** {session.status}  ",
            "",
            "---",
            "",
            "## Summary",
            "",
            "| Metric | Count |",
            "|--------|-------|",
            f"| Total Requests | {session.total_requests} |",
            f"| Total Findings | {session.total_findings} |",
            f"| 🔴 Critical | {session.critical_count} |",
            f"| 🟠 High | {session.high_count} |",
            f"| 🟡 Medium | {session.medium_count} |",
            f"| 🔵 Low | {session.low_count} |",
            f"| ⚪ Informational | {session.info_count} |",
            "",
            "---",
            "",
            "## Findings",
            "",
        ]

        if not findings:
            lines.append("✅ **Nenhum finding identificado.**")
        else:
            sorted_findings = sorted(
                findings,
                key=lambda f: _SEVERITY_ORDER.index(f.severity)
                if f.severity in _SEVERITY_ORDER else 99,
            )

            for i, f in enumerate(sorted_findings, 1):
                badge = _SEVERITY_BADGES.get(f.severity, f.severity.upper())
                refs = []
                try:
                    refs = json.loads(f.references or "[]")
                except Exception:
                    pass

                lines += [
                    f"### {i}. {f.title}",
                    "",
                    f"**Severity:** {badge}  ",
                    f"**Type:** `{f.vulnerability_type}`  ",
                    f"**Endpoint:** `{f.affected_endpoint}`  ",
                    "",
                    "#### Description",
                    "",
                    f.description,
                    "",
                    "#### Evidence",
                    "",
                    "```",
                    f.evidence[:800],
                    "```",
                    "",
                    "#### Recommendation",
                    "",
                    f.recommendation,
                    "",
                ]

                if refs:
                    lines += ["#### References", ""]
                    for ref in refs:
                        lines.append(f"- {ref}")
                    lines.append("")

                if f.false_positive_likelihood:
                    lines.append(
                        f"*False Positive Likelihood: {f.false_positive_likelihood}*"
                    )
                    lines.append("")

                lines.append("---")
                lines.append("")

        lines += [
            "",
            "---",
            "*Generated by [Trickster](https://github.com/trickster-security/trickster) v1.0.0 — Passive HTTP Analysis & Vulnerability Scanner*",
        ]

        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        logger.info("report_markdown_generated", path=str(output_path))
        return output_path

    def generate(
        self,
        session: ScanSessionModel,
        findings: List[FindingModel],
    ) -> Dict[str, Path]:
        """
        Gera todos os relatórios configurados.
        
        Returns:
            Dicionário {formato: caminho_do_arquivo}
        """
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_target = session.target_url.replace("://", "_").replace("/", "_")[:50]
        base_name = f"trickster_{safe_target}_{ts}"

        generated: Dict[str, Path] = {}

        for fmt in self._formats:
            output_path = self._output_dir / f"{base_name}.{fmt}"

            try:
                if fmt == "json":
                    generated["json"] = self.generate_json(session, findings, output_path)
                elif fmt == "html":
                    generated["html"] = self.generate_html(session, findings, output_path)
                elif fmt in ("markdown", "md"):
                    generated["markdown"] = self.generate_markdown(
                        session, findings, output_path.with_suffix(".md")
                    )
                else:
                    logger.warning("unknown_report_format", format=fmt)
            except Exception as exc:
                logger.error("report_generation_error", format=fmt, error=str(exc))

        return generated


def _escape_html(text: str) -> str:
    """Escapa caracteres HTML para evitar XSS no relatório."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )

