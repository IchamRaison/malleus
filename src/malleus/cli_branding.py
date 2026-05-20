from __future__ import annotations

from collections.abc import Mapping

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

MALLEUS_ASCII = r"""
MALLEUS
███╗   ███╗ █████╗ ██╗     ██╗     ███████╗██╗   ██╗███████╗
████╗ ████║██╔══██╗██║     ██║     ██╔════╝██║   ██║██╔════╝
██╔████╔██║███████║██║     ██║     █████╗  ██║   ██║███████╗
██║╚██╔╝██║██╔══██║██║     ██║     ██╔══╝  ██║   ██║╚════██║
██║ ╚═╝ ██║██║  ██║███████╗███████╗███████╗╚██████╔╝███████║
╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝ ╚═════╝ ╚══════╝
""".strip("\n")

MOTTO = "Audit • Harden • Prove"
POSITIONING = "Evidence-first agent security assessment for LLMs and AI systems"


def _console(*, color: bool = True) -> Console:
    return Console(color_system="auto" if color else None, force_terminal=False, width=100, highlight=False)


def render_success(message: str, *, color: bool = True) -> str:
    console = _console(color=color)
    with console.capture() as capture:
        console.print(f"[bold green]✓[/bold green] {message}")
    return capture.get()


def render_command_summary(title: str, values: Mapping[str, object], *, color: bool = True) -> str:
    console = _console(color=color)
    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold cyan", no_wrap=True)
    table.add_column(style="white")
    for key, value in values.items():
        table.add_row(str(key), str(value))
    panel = Panel(table, title=f"[bold violet]{title}[/bold violet]", border_style="violet", box=box.ROUNDED)
    with console.capture() as capture:
        console.print(panel)
    return capture.get()


def render_splash(*, version: str | None = None, color: bool = True) -> str:
    console = _console(color=color)
    commands = Table.grid(padding=(0, 2))
    commands.add_column(style="bold cyan", no_wrap=True)
    commands.add_column(style="white")
    commands.add_row("◆ malleus target init", "guided provider/model setup")
    commands.add_row("◇ malleus target doctor <target> --live-check", "auth, endpoint, and capability preflight")
    commands.add_row("▶ malleus benchmark soft --target <target>", "fast live benchmark with trace evidence")
    commands.add_row("◉ malleus benchmark exterminatus --target <target>", "full surface sweep")
    commands.add_row("▣ malleus evidence-bundle", "public report bundle from local artifacts")

    legend = Table.grid(padding=(0, 2))
    legend.add_column(style="bold white", no_wrap=True)
    legend.add_column(style="white")
    legend.add_row("✓ pass", "credible evidence satisfied the checks")
    legend.add_row("✗ fail", "model or system behavior violated a check")
    legend.add_row("⚠ gap/error", "coverage, provider, target, or harness issue")
    legend.add_row("◆ checkpoint", "partial progress written and resumable evidence available")

    subtitle = POSITIONING if version is None else f"{POSITIONING}\nversion: malleus-evals {version}"
    body = Text()
    body.append(MALLEUS_ASCII, style="bold bright_white")
    body.append("\n")
    body.append(MOTTO, style="bold violet")
    body.append("\n")
    body.append(subtitle, style="white")

    with console.capture() as capture:
        console.print(Panel(body, border_style="bright_black", box=box.HEAVY, padding=(1, 2)))
        console.print(Panel(commands, title="[bold]Operator flow[/bold]", border_style="cyan", box=box.ROUNDED))
        console.print(Panel(legend, title="[bold]Live run legend[/bold]", border_style="green", box=box.ROUNDED))
        console.print("[dim]Normal benchmark evidence is live/provider-backed. Dry-run and provider-free outputs are planning evidence, not model verdicts.[/dim]")
    return capture.get()
