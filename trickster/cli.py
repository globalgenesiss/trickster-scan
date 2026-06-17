"""trickster/cli.py — Interface de linha de comando."""

import asyncio
import click
from rich.console import Console

console = Console()

@click.group()
def cli():
    """Trickster — HTTP Analysis & Vulnerability Scanner."""
    pass

@cli.command()
@click.argument("url")
def scan(url: str):
    """Executa analise de seguranca em uma URL."""
    from trickster.utils.logger import setup_logging
    from trickster.scanner import Scanner

    setup_logging()

    async def _run():
        console.print(f"\n[bold cyan]Iniciando scan em:[/bold cyan] {url}\n")
        scanner = Scanner()
        session_id = await scanner.run(url=url)
        console.print(f"\n[bold green]Scan concluido! Session ID: {session_id}[/bold green]")
        console.print(f"[dim]Relatorios salvos em: ./output[/dim]\n")

    asyncio.run(_run())

@cli.command("list")
def list_sessions():
    """Lista sessoes anteriores."""
    from trickster.utils.logger import setup_logging
    from trickster.database.repository import get_repository, init_database

    setup_logging()

    async def _list():
        await init_database()
        async with get_repository() as repo:
            sessions = await repo.list_sessions(limit=10)
        if not sessions:
            console.print("[yellow]Nenhuma sessao encontrada.[/yellow]")
            return
        for s in sessions:
            console.print(f"[cyan]{s.id[:8]}[/cyan] | {s.target_url} | {s.status} | findings: {s.total_findings}")

    asyncio.run(_list())

def main():
    cli()

if __name__ == "__main__":
    main()
