"""
trickster/config.py
"""
 
from __future__ import annotations
 
from enum import Enum
from pathlib import Path
from typing import List
 
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
 
 
class AIProvider(str, Enum):
    """Provedores de IA."""
    ANTHROPIC = "anthropic"
    OPENAI = "openai"
 
 
class LogLevel(str, Enum):
    """Níveis de log disponíveis."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
 
 
class Settings(BaseSettings):
    """
    Configurações centrais da aplicação.
    
    Todas as variáveis podem ser sobrescritas via arquivo .env
    ou variáveis de ambiente com prefixo HAWK_ (opcional).
    """
 
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",  # Ignora variáveis não declaradas no .env
    )
 
    # ── Provedor de IA ─────────────────────────────────────────────────────────
    ai_provider: AIProvider = Field(
        default=AIProvider.ANTHROPIC,
        description="Provedor de IA: 'anthropic' ou 'openai'",
    )
 
    # Anthropic
    anthropic_api_key: str = Field(default="", description="Chave da API Anthropic")
    anthropic_model: str = Field(
        default="claude-sonnet-4-6",
        description="Modelo Claude a utilizar",
    )
    anthropic_max_tokens: int = Field(default=4096, ge=256, le=8192)
 
    # OpenAI
    openai_api_key: str = Field(default="", description="Chave da API OpenAI")
    openai_model: str = Field(default="gpt-4o")
    openai_max_tokens: int = Field(default=4096, ge=256, le=8192)

    # Groq (gratuito)
    groq_api_key: str = Field(default="", description="Chave da API Groq")
    groq_model: str = Field(default="llama-3.3-70b-versatile")
 
    # ── Banco de Dados ─────────────────────────────────────────────────────────
    database_url: str = Field(
        default="sqlite+aiosqlite:///./hawk.db",
        description="URL de conexão SQLAlchemy (SQLite ou PostgreSQL)",
    )
 
    # ── Proxy MITM ─────────────────────────────────────────────────────────────
    proxy_host: str = Field(default="127.0.0.1")
    proxy_port: int = Field(default=8080, ge=1024, le=65535)
    proxy_ssl_insecure: bool = Field(
        default=True,
        description="Aceitar certificados auto-assinados do proxy MITM",
    )
 
    # ── Configurações do Browser ───────────────────────────────────────────────
    browser_timeout: int = Field(
        default=30,
        ge=0,
        le=999999,
        description="Timeout geral do browser em segundos (0 = sem limite)",
    )
    idle_timeout: int = Field(
        default=15,
        ge=0,
        le=99999,
        description="Aguardar rede ociosa por N segundos antes de encerrar",
    )
    browser_headless: bool = Field(
        default=True,
        description="Executar browser sem interface gráfica",
    )
 
    # ── Análise de IA ──────────────────────────────────────────────────────────
    max_body_size: int = Field(
        default=10240,
        ge=512,
        description="Tamanho máximo do body (bytes) enviado à IA",
    )
    ai_batch_size: int = Field(
        default=10,
        ge=1,
        le=50,
        description="Requisições agrupadas por prompt de análise",
    )
 
    # ── Relatórios ─────────────────────────────────────────────────────────────
    output_dir: Path = Field(
        default=Path("./output"),
        description="Diretório de saída para relatórios",
    )
    report_formats: List[str] = Field(
        default=["json", "html", "markdown"],
        description="Formatos de relatório a gerar",
    )
 
    # ── Logs ───────────────────────────────────────────────────────────────────
    log_level: LogLevel = Field(default=LogLevel.INFO)
    log_file: Path = Field(default=Path("./hawk.log"))
 
    # ── Validadores ────────────────────────────────────────────────────────────
    @field_validator("report_formats", mode="before")
    @classmethod
    def parse_report_formats(cls, v: str | List[str]) -> List[str]:
        """Aceita string separada por vírgula ou lista."""
        if isinstance(v, str):
            return [fmt.strip().lower() for fmt in v.split(",") if fmt.strip()]
        return [fmt.lower() for fmt in v]
 
    @field_validator("output_dir", mode="before")
    @classmethod
    def ensure_output_dir(cls, v: str | Path) -> Path:
        """Garante que o diretório de saída existe."""
        path = Path(v)
        path.mkdir(parents=True, exist_ok=True)
        return path
 
    def get_proxy_url(self) -> str:
        """Retorna a URL completa do proxy."""
        return f"http://{self.proxy_host}:{self.proxy_port}"
 
    def get_ai_api_key(self) -> str:
        """Retorna a chave de API do provedor configurado."""
        if self.ai_provider == AIProvider.ANTHROPIC:
            return self.anthropic_api_key
        return self.openai_api_key
 
    def get_ai_model(self) -> str:
        """Retorna o modelo do provedor configurado."""
        if self.ai_provider == AIProvider.ANTHROPIC:
            return self.anthropic_model
        return self.openai_model
 
    def get_ai_max_tokens(self) -> int:
        """Retorna o max_tokens do provedor configurado."""
        if self.ai_provider == AIProvider.ANTHROPIC:
            return self.anthropic_max_tokens
        return self.openai_max_tokens
 
 
# ── Instância global (singleton) ───────────────────────────────────────────────
# Importar de qualquer módulo: trickster.config import settings
settings = Settings()

