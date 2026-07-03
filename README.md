\#  TRICKSTER



Scanner de vulnerabilidades HTTP/HTTPS com IA. Você navega no site, ele captura tudo e manda pra uma IA analisar.



\---



\## Como funciona



O TRICKSTER abre um browser real na sua máquina. Enquanto você usa o site normalmente — faz login, preenche formulário, clica em botões — ele intercepta todas as requisições e respostas HTTP em segundo plano via Chrome DevTools Protocol.



Quando você terminar e pressionar Enter, ele pega todo esse tráfego capturado e manda pro \*\*LLaMA 3.3 70B\*\* rodando na Groq. O modelo analisa cada requisição procurando falhas de segurança e devolve um JSON estruturado com os findings.



No final gera um relatório em HTML, JSON e Markdown.



\---



\## O que detecta



\- Senha ou token expostos em URL via GET

\- Parâmetros controlando privilégios (`is\_admin=True`, `role=admin`)

\- IDOR — IDs sequenciais em endpoints

\- XSS, SQL Injection, Path Traversal

\- Cookies sem `HttpOnly`, `Secure` ou `SameSite`

\- Headers ausentes — CSP, HSTS, X-Frame-Options

\- CORS aberto com `\*`

\- Formulários sem token CSRF

\- Stack traces e informações internas em responses



\---



\## Requisitos



\- Python 3.12+

\- Conta gratuita no \[Groq](https://console.groq.com)



\---



\## Instalação



```bash

git clone https://github.com/globalgenesiss/trickster-scan.git

cd trickster-scanner



python -m venv .venv



\# Windows

.venv\\Scripts\\activate



\# Linux/macOS

source .venv/bin/activate



pip install -r trickster/requierements.txt

pip install openai

playwright install chromium

pip install -e .

```



Crie o `.env` na raiz do projeto:



```env

GROQ\_API\_KEY=sua\_chave\_aqui

GROQ\_MODEL=llama-3.3-70b-versatile

BROWSER\_HEADLESS=false

BROWSER\_TIMEOUT=0

OUTPUT\_DIR=./output

REPORT\_FORMATS=\["json","html","markdown"]

LOG\_LEVEL=INFO

```



Chave gratuita em \[console.groq.com](https://console.groq.com).



\---



\## Uso



```bash

python -m trickster.cli scan https://alvo.com

```



O browser abre. Você navega, testa, faz login. Quando terminar pressiona Enter. Os relatórios aparecem em `output/`.



```bash

\# Ver sessões anteriores

python -m trickster.cli list



\# Regenerar relatório de uma sessão

python -m trickster.cli report <session\_id>

```



\---



\## Stack



\- \*\*Playwright\*\* — interceptação de tráfego via CDP

\- \*\*Groq + LLaMA 3.3 70B\*\* — análise de vulnerabilidades

\- \*\*SQLAlchemy + SQLite\*\* — persistência local

\- \*\*Click\*\* — CLI

\- \*\*Pydantic\*\* — configuração e validação



