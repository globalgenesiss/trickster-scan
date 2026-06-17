"""
trickster/utils/normalizer.py
========================
Normaliza e enriquece dados brutos de requisições/respostas HTTP.
 
Responsabilidades:
- Extrair JWTs e tokens de autenticação de headers e cookies
- Decodificar bodies (JSON, form-data, multipart)
- Normalizar headers para comparação case-insensitive
- Truncar bodies grandes para análise por IA
- Identificar Content-Type e encoding
"""
 
from __future__ import annotations
 
import base64
import json
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote_plus, urlparse
 
from trickster.utils.logger import get_logger
 
logger = get_logger(__name__)
 
# ── Padrões de detecção ───────────────────────────────────────────────────────
 
# JWT: três segmentos base64url separados por pontos
_JWT_PATTERN = re.compile(
    r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"
)
 
# Bearer token genérico
_BEARER_PATTERN = re.compile(
    r"Bearer\s+([A-Za-z0-9\-._~+/]+=*)", re.IGNORECASE
)
 
# Basic auth
_BASIC_PATTERN = re.compile(
    r"Basic\s+([A-Za-z0-9+/]+=*)", re.IGNORECASE
)
 
# API keys comuns (chaves com 20+ caracteres alfanuméricos ou com prefixos conhecidos)
_API_KEY_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9]{32,}"),          # OpenAI / Anthropic style
    re.compile(r"ghp_[A-Za-z0-9]{36}"),           # GitHub Personal Access Token
    re.compile(r"xoxb-[0-9-]{50,}"),              # Slack bot token
    re.compile(r"AKIA[A-Z0-9]{16}"),              # AWS Access Key ID
]
 
 
def extract_query_params(url: str) -> Dict[str, str]:
    """
    Extrai parâmetros de query string de uma URL.
    Valores múltiplos são concatenados com vírgula.
    """
    parsed = urlparse(url)
    raw_params = parse_qs(parsed.query, keep_blank_values=True)
    return {k: ", ".join(v) for k, v in raw_params.items()}
 
 
def normalize_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """
    Normaliza chaves de headers para lowercase.
    Facilita comparações case-insensitive.
    """
    return {k.lower(): v for k, v in (headers or {}).items()}
 
 
def extract_cookies(cookie_header: Optional[str]) -> Dict[str, str]:
    """
    Extrai cookies do header 'Cookie' ou 'Set-Cookie'.
    Retorna dicionário nome → valor.
    """
    if not cookie_header:
        return {}
 
    cookies: Dict[str, str] = {}
    # Suporta tanto "Cookie: name=value; name2=value2"
    # quanto "Set-Cookie: name=value; Path=/; HttpOnly"
    parts = cookie_header.split(";")
    for part in parts:
        part = part.strip()
        if "=" in part:
            name, _, value = part.partition("=")
            name = name.strip()
            value = value.strip()
            # Ignorar atributos do Set-Cookie (Path, Domain, HttpOnly, etc.)
            if name.lower() not in {
                "path", "domain", "expires", "max-age",
                "secure", "httponly", "samesite",
            }:
                cookies[name] = unquote_plus(value)
    return cookies
 
 
def extract_jwt_tokens(text: str) -> List[str]:

    return list(set(_JWT_PATTERN.findall(text)))
 
 
def decode_jwt_payload(token: str) -> Optional[Dict[str, Any]]:

    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        # Adiciona padding base64 se necessário
        payload_b64 = parts[1] + "==" * (-len(parts[1]) % 4)
        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        return json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        return None
 
 
def extract_auth_tokens(headers: Dict[str, str], body: Optional[str] = None) -> List[str]:

    tokens: List[str] = []
    text_sources = list(headers.values())
    if body:
        text_sources.append(body)
 
    full_text = " ".join(text_sources)
 
    # Bearer tokens
    tokens.extend(_BEARER_PATTERN.findall(full_text))
 
    # Basic auth (decodifica para análise, mas marca como sensível)
    for match in _BASIC_PATTERN.finditer(full_text):
        tokens.append(f"BASIC:{match.group(1)}")
 
    # API keys com padrões conhecidos
    for pattern in _API_KEY_PATTERNS:
        tokens.extend(pattern.findall(full_text))
 
    return list(set(tokens))
 
 
def decode_body(
    body_bytes: Optional[bytes],
    content_type: Optional[str],
    max_size: int = 10240,
) -> Tuple[Optional[str], int]:
    """
    Decodifica o body da requisição/resposta para string.
 
    Args:
        body_bytes: Bytes brutos do body
        content_type: Content-Type header
        max_size: Tamanho máximo em bytes para preservar
 
    Returns:
        Tupla (body_str, tamanho_original)
    """
    if not body_bytes:
        return None, 0
 
    original_size = len(body_bytes)
    truncated = body_bytes[:max_size]
 
    ct = (content_type or "").lower()
 
    try:
        # Tenta UTF-8 primeiro
        decoded = truncated.decode("utf-8")
    except UnicodeDecodeError:
        try:
            decoded = truncated.decode("latin-1")
        except UnicodeDecodeError:
            # Body binário: representa em hex truncado
            decoded = f"[BINARY:{original_size} bytes] {truncated[:64].hex()}"
 
    # Formata JSON para melhor legibilidade
    if "json" in ct:
        try:
            parsed = json.loads(decoded)
            decoded = json.dumps(parsed, ensure_ascii=False, indent=2)
        except json.JSONDecodeError:
            pass  # Mantém como string bruta
 
    if original_size > max_size:
        decoded += f"\n... [TRUNCADO: {original_size} bytes originais]"
 
    return decoded, original_size
 
 
def build_request_summary(
    url: str,
    method: str,
    headers: Dict[str, str],
    query_params: Dict[str, str],
    body: Optional[str],
    cookies: Dict[str, str],
    jwt_tokens: List[str],
    auth_tokens: List[str],
    response_status: Optional[int] = None,
    response_headers: Optional[Dict[str, str]] = None,
    response_body: Optional[str] = None,
) -> str:

    lines: List[str] = []
 
    # ── Request ────────────────────────────────────────────────────────────────
    lines.append(f"=== REQUEST ===")
    lines.append(f"Method: {method}")
    lines.append(f"URL: {url}")
 
    if query_params:
        lines.append("Query Params:")
        for k, v in query_params.items():
            lines.append(f"  {k}: {v}")
 
    lines.append("Request Headers:")
    for k, v in headers.items():
        lines.append(f"  {k}: {v}")
 
    if cookies:
        lines.append("Cookies:")
        for k, v in cookies.items():
            # Mascara valores de cookies por privacidade, mantém nome
            lines.append(f"  {k}: {v[:20]}..." if len(v) > 20 else f"  {k}: {v}")
 
    if jwt_tokens:
        lines.append(f"JWT Tokens Found: {len(jwt_tokens)}")
        for token in jwt_tokens[:3]:  # máximo 3 tokens no prompt
            payload = decode_jwt_payload(token)
            if payload:
                # Remove dados sensíveis mas mantém estrutura
                safe_payload = {
                    k: v for k, v in payload.items()
                    if k in {"iss", "sub", "aud", "exp", "iat", "nbf", "jti", "role", "scope", "email"}
                }
                lines.append(f"  JWT Payload: {json.dumps(safe_payload)}")
 
    if auth_tokens:
        lines.append(f"Auth Tokens Found: {len(auth_tokens)} (masked)")
 
    if body:
        lines.append(f"Request Body:\n{body[:2048]}")
 
    # ── Response ───────────────────────────────────────────────────────────────
    if response_status is not None:
        lines.append(f"\n=== RESPONSE ===")
        lines.append(f"Status: {response_status}")
 
        if response_headers:
            lines.append("Response Headers:")
            for k, v in response_headers.items():
                lines.append(f"  {k}: {v}")
 
        if response_body:
            lines.append(f"Response Body (excerpt):\n{response_body[:2048]}")
 
    return "\n".join(lines)

