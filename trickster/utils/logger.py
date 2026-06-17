"""
trickster/utils/logger.py
====================
Configura o sistema de logs.
"""
 
from __future__ import annotations
 
import logging
import sys
from pathlib import Path
from typing import Any
 
import structlog
from structlog.types import EventDict, WrappedLogger
 
from trickster.config import settings
 
 
def _add_log_level(
    logger: WrappedLogger,
    method_name: str,
    event_dict: EventDict,
) -> EventDict:
    """Adiciona o nível de log ao evento estruturado."""
    event_dict["level"] = method_name.upper()
    return event_dict
 
 
def setup_logging() -> None:
    log_level = getattr(logging, settings.log_level.value, logging.INFO)
 
    # ── Processadores compartilhados ──────────────────────────────────────────
    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,          # Contexto de requisição
        structlog.stdlib.add_logger_name,                 # Nome do logger
        _add_log_level,                                   # Nível de log
        structlog.stdlib.PositionalArgumentsFormatter(),  # Formatação de args
        structlog.processors.TimeStamper(fmt="iso"),      # Timestamp ISO 8601
        structlog.processors.StackInfoRenderer(),         # Stack traces
        structlog.processors.UnicodeDecoder(),            # Garantia UTF-8
    ]
 
    # ── Configuração do stdlib logging ────────────────────────────────────────
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=log_level,
    )
 
    # Handler de arquivo em JSON
    log_file: Path = settings.log_file
    log_file.parent.mkdir(parents=True, exist_ok=True)
 
    file_handler = logging.FileHandler(str(log_file), encoding="utf-8")
    file_handler.setLevel(log_level)
 
    root_logger = logging.getLogger()
    root_logger.addHandler(file_handler)
 
    # Silenciar logs ruidosos de bibliotecas externas
    for noisy_lib in ["playwright", "asyncio", "httpcore", "httpx"]:
        logging.getLogger(noisy_lib).setLevel(logging.WARNING)
 
    # ── Configuração do structlog ─────────────────────────────────────────────
    structlog.configure(
        processors=shared_processors
        + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
 
    # Formatter para console (colorido)
    console_formatter = structlog.stdlib.ProcessorFormatter(
        processor=structlog.dev.ConsoleRenderer(colors=True),
        foreign_pre_chain=shared_processors,
    )
 
    # Formatter para arquivo (JSON)
    json_formatter = structlog.stdlib.ProcessorFormatter(
        processor=structlog.processors.JSONRenderer(),
        foreign_pre_chain=shared_processors,
    )
 
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(console_formatter)
    console_handler.setLevel(log_level)
 
    file_handler.setFormatter(json_formatter)
 
    root_logger.handlers = [console_handler, file_handler]
    root_logger.setLevel(log_level)
 
 
def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)

