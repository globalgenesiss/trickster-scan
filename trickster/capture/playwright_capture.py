"""
trickster/capture/playwright_capture.py
====================================
Motor de captura de tráfego HTTP/HTTPS usando Playwright + CDP.

Estratégia técnica escolhida:
    Playwright com Chrome DevTools Protocol (CDP) via request interception.
    
    Justificativa sobre as alternativas:
    - mitmproxy: Excelente para HTTPS, mas requer instalação de certificado
      no sistema e configuração de proxy no browser — adiciona complexidade.
    - Selenium + BrowserMob Proxy: Mais pesado, proxy Java separado, latência.
    - CDP direto: Possível mas requer websocket manual sem abstração.
    - Playwright + CDP (escolhido): Integra browser automation + interceptação
      de rede nativamente, suporte HTTPS via route interception, sem proxy
      externo, async-first, tipagem excelente.

Fluxo de captura:
    1. Inicializa Chromium headless com Playwright
    2. Registra interceptadores de request e response via page.on()
    3. Navega até a URL alvo
    4. Aguarda a rede ficar ociosa (networkidle)
    5. Registra todos os pares request/response no banco
"""

from __future__ import annotations

import asyncio
import time
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse

from playwright.async_api import (
    Browser,
    BrowserContext,
    Page,
    Request,
    Response,
    async_playwright,
)

from trickster.config import settings
from trickster.utils.logger import get_logger
from trickster.utils.models import HttpRequest, HttpResponse
from trickster.utils.normalizer import (
    decode_body,
    extract_auth_tokens,
    extract_cookies,
    extract_jwt_tokens,
    extract_query_params,
    normalize_headers,
)

logger = get_logger(__name__)

# ── Tipos ─────────────────────────────────────────────────────────────────────

# Callback invocado ao capturar um par request/response
OnCapture = Callable[[HttpRequest, HttpResponse], None]


# ── Filtros de URL ─────────────────────────────────────────────────────────────

_SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif",
    ".woff", ".woff2", ".ttf", ".otf",
    ".mp4", ".webm", ".mp3",
}

_SKIP_DOMAINS: set = set()


def _should_skip(url: str, target_domain: str) -> bool:
    """
    Determina se uma URL deve ser ignorada durante a captura.
    Foca nas requisições do domínio alvo e APIs relacionadas.
    """
    try:
        parsed = urlparse(url)
        # Ignora recursos estáticos
        path = parsed.path.lower()
        if any(path.endswith(ext) for ext in _SKIP_EXTENSIONS):
            return True
        # Ignora domínios de rastreamento/analytics
        netloc = parsed.netloc.lower()
        if any(skip in netloc for skip in _SKIP_DOMAINS):
            return True
        return False
    except Exception:
        return False


# ── Classe principal de captura ────────────────────────────────────────────────

class PlaywrightCapture:
    """
    Captura tráfego HTTP/HTTPS usando Playwright com interceptação de rede.
    
    Exemplo de uso:
        async with PlaywrightCapture() as capture:
            pairs = await capture.capture(
                url="https://exemplo.com",
                session_id="uuid-da-sessao",
            )
    """

    def __init__(self) -> None:
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None
        self._playwright = None
        
        # Buffer para armazenar dados capturados
        self._requests: Dict[str, HttpRequest] = {}
        self._responses: Dict[str, HttpResponse] = {}
        self._captured_pairs: List[tuple[HttpRequest, HttpResponse]] = []

    async def __aenter__(self) -> "PlaywrightCapture":
        """Inicializa o Playwright e abre o browser."""
        await self._start()
        return self

    async def __aexit__(self, *args) -> None:
        """Fecha o browser e libera recursos."""
        await self._stop()

    async def _start(self) -> None:
        """Inicializa o browser Chromium com configurações de segurança."""
        logger.info("browser_starting", headless=settings.browser_headless)
        self._playwright = await async_playwright().start()
        
        self._browser = await self._playwright.chromium.launch(
            headless=settings.browser_headless,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-blink-features=AutomationControlled",
                "--ignore-certificate-errors",  # Necessário para HTTPS auto-assinado
            ],
        )
        logger.info("browser_started")

    async def _stop(self) -> None:
        """Encerra o browser e o Playwright."""
        if self._context:
            await self._context.close()
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()
        logger.info("browser_stopped")

    async def capture(
        self,
        url: str,
        session_id: str,
        on_capture: Optional[OnCapture] = None,
    ) -> List[tuple[HttpRequest, HttpResponse]]:
        """
        Navega até a URL alvo e captura todo o tráfego HTTP/HTTPS.
        
        Args:
            url: URL do site a ser analisado
            session_id: ID da sessão de scan para associar as capturas
            on_capture: Callback opcional chamado para cada par request/response
            
        Returns:
            Lista de tuplas (HttpRequest, HttpResponse) capturadas
        """
        self._requests = {}
        self._responses = {}
        self._captured_pairs = []

        target_domain = urlparse(url).netloc
        logger.info("capture_starting", url=url, session_id=session_id)

        # Cria um novo contexto de browser com configurações de segurança
        self._context = await self._browser.new_context(
            ignore_https_errors=True,  # Aceita certificados inválidos
            java_script_enabled=True,
            accept_downloads=False,
            # User agent realístico para evitar bloqueios por bot detection
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
        )

        page: Page = await self._context.new_page()

        # ── Interceptadores no CONTEXTO inteiro (todas as páginas/abas) ────────

        async def _on_request(request: Request) -> None:
            """Captura dados de cada requisição."""
            if _should_skip(request.url, target_domain):
                return

            try:
                raw_headers = dict(request.headers)
                headers = normalize_headers(raw_headers)
                
                # Extrai body da requisição
                body_str: Optional[str] = None
                body_size = 0
                try:
                    post_data = request.post_data
                    if post_data:
                        body_str = post_data
                        body_size = len(post_data.encode("utf-8", errors="replace"))
                except Exception:
                    pass

                # Extrai cookies do header Cookie
                cookies = extract_cookies(headers.get("cookie"))
                
                # Busca JWTs em todos os contextos da requisição
                search_text = (
                    " ".join(raw_headers.values())
                    + (body_str or "")
                    + str(cookies)
                )
                jwt_tokens = extract_jwt_tokens(search_text)
                auth_tokens = extract_auth_tokens(headers, body_str)

                http_request = HttpRequest(
                    session_id=session_id,
                    url=request.url,
                    method=request.method,
                    headers=raw_headers,
                    query_params=extract_query_params(request.url),
                    body=body_str,
                    body_size=body_size,
                    cookies=cookies,
                    jwt_tokens=jwt_tokens,
                    auth_tokens=auth_tokens,
                    content_type=headers.get("content-type"),
                    is_https=request.url.startswith("https://"),
                )
                
                # Armazena pelo ID interno do Playwright para correlação
                self._requests[request.url + request.method] = http_request
                logger.debug(
                    "request_captured",
                    method=request.method,
                    url=request.url[:100],
                )
            except Exception as exc:
                logger.warning("request_capture_error", error=str(exc), url=request.url[:100])

        async def _on_response(response: Response) -> None:
            """Captura dados de cada resposta."""
            if _should_skip(response.url, target_domain):
                return

            key = response.url + response.request.method
            matched_request = self._requests.get(key)
            if not matched_request:
                return

            try:
                start_time = time.monotonic()
                raw_headers = dict(response.headers)
                headers = normalize_headers(raw_headers)

                # Tenta ler o body da resposta
                body_str: Optional[str] = None
                body_size = 0
                try:
                    body_bytes = await response.body()
                    content_type = headers.get("content-type", "")
                    body_str, body_size = decode_body(
                        body_bytes,
                        content_type,
                        max_size=settings.max_body_size,
                    )
                except Exception:
                    pass

                duration_ms = (time.monotonic() - start_time) * 1000

                http_response = HttpResponse(
                    request_id=matched_request.id,
                    session_id=session_id,
                    status_code=response.status,
                    headers=raw_headers,
                    body=body_str,
                    body_size=body_size,
                    content_type=headers.get("content-type"),
                    duration_ms=duration_ms,
                )

                self._responses[matched_request.id] = http_response

                # Emite o par para o callback (se fornecido)
                self._captured_pairs.append((matched_request, http_response))
                if on_capture:
                    await asyncio.coroutine(lambda: on_capture(matched_request, http_response))() \
                        if asyncio.iscoroutinefunction(on_capture) \
                        else on_capture(matched_request, http_response)

                logger.debug(
                    "response_captured",
                    status=response.status,
                    url=response.url[:100],
                    body_size=body_size,
                )
            except Exception as exc:
                logger.warning("response_capture_error", error=str(exc), url=response.url[:100])

        # Registra os interceptadores
        self._context.on("request", _on_request)
        self._context.on("response", _on_response)

       # ── Navegação ──────────────────────────────────────────────────────────
        try:
            logger.info("navigating", url=url)
            await page.goto(
                url,
                timeout=0,
                wait_until="domcontentloaded",
            )

            # Modo interativo — usuário navega livremente
            print("\n" + "="*50)
            print("  BROWSER ABERTO — navegue normalmente")
            print("  Faça login, interaja com o site...")
            print("  Quando terminar, volte aqui e pressione ENTER")
            print("="*50 + "\n")
            input()            
            logger.info(
                "capture_completed",
                url=url,
                pairs_captured=len(self._captured_pairs),
            )
        except Exception as exc:
            logger.error("navigation_error", error=str(exc), url=url)
            raise

        finally:
            await page.close()

        return self._captured_pairs

