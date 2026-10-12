# Console UI — Rich-обёртки для AEGIS (v2: лог, секции, карточки)

import sys
import time
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.rule import Rule
from rich.align import Align
from rich.live import Live
from rich.spinner import Spinner


console = Console()


# ============================================================
# BANNER
# ============================================================

AEGIS_ASCII = r"""
   ▄▄▄       ▓█████   ▄████  ██▓  ██████
  ▒████▄     ▓█   ▀  ██▒ ▀█▒▓██▒▒██    ▒
  ▒██  ▀█▄   ▒███   ▒██░▄▄▄░▒██▒░ ▓██▄
  ░██▄▄▄▄██  ▒▓█  ▄ ░▓█  ██▓░██░  ▒   ██▒
   ▓█   ▓██▒░▒████▒░▒▓███▀▒░██░▒██████▒▒
   ▒▒   ▓▒█░░░ ▒░ ░ ░▒   ▒ ░▓  ▒ ▒▓▒ ▒ ░
    ▒   ▒▒ ░ ░ ░  ░  ░   ░  ▒ ░░ ░▒  ░ ░
    ░   ▒      ░   ░ ░   ░  ▒ ░░  ░  ░
        ░      ░  ░      ░  ░        ░
"""


def banner(target=None):
    console.print()
    console.print(Align.center(
        Text(AEGIS_ASCII, style="bold red"),
    ))
    console.print(Align.center(
        Text("Autonomous Exploitation & Guidance Intelligence System",
             style="dim cyan"),
    ))
    console.print(Align.center(
        Text("Только для авторизованного пентеста", style="dim yellow"),
    ))
    console.print()
    if target:
        console.print(Panel(
            f"[bold white]Цель:[/bold white] [cyan]{target}[/cyan]",
            border_style="red",
            padding=(0, 2),
        ))
    console.print()


# ============================================================
# СЕКЦИИ
# ============================================================

def section(number, total, title):
    """Заголовок секции: [2/7] nmap"""
    console.print()
    console.print(Rule(
        f"[bold yellow]\\[{number}/{total}][/bold yellow]  "
        f"[bold white]{title}[/bold white]",
        style="yellow",
        align="left",
    ))


def info(msg):
    console.print(f"  [dim]{msg}[/dim]")


def ok(msg):
    console.print(f"  [green]✓[/green] {msg}")


def warn(msg):
    console.print(f"  [yellow]![/yellow] {msg}")


def err(msg):
    console.print(f"  [red]✗[/red] {msg}")


def kv(key, value, key_style="cyan", value_style="white"):
    console.print(f"  [{key_style}]{key}:[/{key_style}] [{value_style}]{value}[/{value_style}]")


def step(emoji, text):
    console.print(f"  [bold cyan]{emoji}[/bold cyan] {text}")


# ============================================================
# LIVE-ЛОГ
# ============================================================

class LiveLog:
    """
    Живой лог с таймстампами.
    Использование:
        with LiveLog() as log:
            log.info("nmap старт")
            log.ok("nmap готов")
    """
    def __init__(self, console=None):
        self.console = console or globals()["console"]
        self._live = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def _ts(self):
        return datetime.now().strftime("%H:%M:%S")

    def info(self, msg):
        self.console.print(f"  [dim]{self._ts()}[/dim] [blue]INFO[/blue]  {msg}")

    def ok(self, msg):
        self.console.print(f"  [dim]{self._ts()}[/dim] [green] OK [/green]  {msg}")

    def warn(self, msg):
        self.console.print(f"  [dim]{self._ts()}[/dim] [yellow]WARN[/yellow]  {msg}")

    def err(self, msg):
        self.console.print(f"  [dim]{self._ts()}[/dim] [red]FAIL[/red]  {msg}")

    def step(self, msg):
        self.console.print(f"  [dim]{self._ts()}[/dim] [cyan]  > [/cyan]  {msg}")


# ============================================================
# КАРТОЧКИ РЕЗУЛЬТАТОВ
# ============================================================

def ports_table(ports, title="Открытые порты"):
    table = Table(title=title, title_style="bold cyan",
                  border_style="dim cyan", show_lines=False)
    table.add_column("Порт", style="bold yellow", justify="right")
    table.add_column("Сервис", style="cyan")
    table.add_column("Версия", style="white")
    table.add_column("CVE", style="red", justify="center")
    for p in ports:
        cve = str(p.get("cve_count", 0)) if p.get("cve_count") else "—"
        table.add_row(
            str(p["port"]),
            p.get("service", "?"),
            (p.get("version") or "")[:50],
            cve,
        )
    console.print(table)


def cve_table(rows):
    """
    rows = [(port, service, count, max_score, top_cves), ...]
    """
    if not rows:
        return
    table = Table(title="CVE по сервисам", title_style="bold red",
                  border_style="dim red", show_lines=False)
    table.add_column("Порт", style="bold yellow", justify="right")
    table.add_column("Сервис", style="cyan")
    table.add_column("CVE", style="white", justify="center")
    table.add_column("Max CVSS", style="red", justify="center")
    table.add_column("Топ", style="dim white")

    for port, svc, cnt, mx, top in rows:
        sev = "[red]CRIT[/red]" if mx >= 9 else \
              "[orange1]HIGH[/orange1]" if mx >= 7 else \
              "[yellow]MED[/yellow]" if mx >= 4 else \
              "[green]LOW[/green]"
        table.add_row(
            str(port),
            svc,
            str(cnt),
            f"{sev} {mx}",
            top,
        )
    console.print(table)


def exploits_table(results):
    """results — список из run_all()."""
    if not results:
        return
    table = Table(title="Эксплуатация", title_style="bold red",
                  border_style="dim red")
    table.add_column("CVE", style="cyan")
    table.add_column("Название", style="white")
    table.add_column("Результат", style="bold", justify="center")

    for r in results:
        if r["result"]["success"]:
            status = "[green]OK[/green]"
        else:
            status = "[yellow]—[/yellow]"
        table.add_row(r["cve"], r["name"], status)
    console.print(table)


def cracked_table(pairs):
    if not pairs:
        return
    table = Table(title="Взломанные учётные данные", title_style="bold green",
                  border_style="dim green")
    table.add_column("Пользователь", style="cyan")
    table.add_column("Пароль", style="bold yellow")
    for u, p in pairs:
        table.add_row(u, p)
    console.print(table)


def final_card(target, n_ports, n_cve, n_exploits, n_cracked, md, pdf, elapsed):
    body = (
        f"[bold green]AEGIS завершён[/bold green]\n\n"
        f"[cyan]Цель:[/cyan]        {target}\n"
        f"[cyan]Портов:[/cyan]      {n_ports}\n"
        f"[cyan]CVE:[/cyan]         {n_cve}\n"
        f"[cyan]Эксплойтов:[/cyan]  {n_exploits}\n"
        f"[cyan]Взломано:[/cyan]    {n_cracked}\n"
        f"[cyan]Время:[/cyan]       {elapsed:.1f} сек\n\n"
        f"[dim]Markdown: {md}[/dim]\n"
        f"[dim]PDF:      {pdf}[/dim]"
    )
    console.print()
    console.print(Panel.fit(body, border_style="green", padding=(1, 2)))


def exploit_log(name, cve, port, version, success, log_text):
    """Красивая карточка одного эксплойта."""
    color = "green" if success else "yellow"
    status = "УСПЕШНО" if success else "НЕ СРАБОТАЛО"
    console.print()
    console.print(Panel(
        f"[bold]{name}[/bold]\n"
        f"[dim]CVE:[/dim] [cyan]{cve}[/cyan]  "
        f"[dim]Порт:[/dim] [yellow]{port}[/yellow]  "
        f"[dim]Версия:[/dim] {version[:50]}\n"
        f"[bold {color}]Статус:[/bold {color}] [{color}]{status}[/{color}]\n\n"
        f"[dim]{log_text[:1500]}[/dim]",
        border_style=color,
        padding=(1, 2),
    ))


if __name__ == "__main__":
    banner("192.168.64.7")
    section(2, 7, "nmap")
    info("старт")
    ok("18 портов")
    warn("кэш не использован")
    err("порт 22 закрыт")

    ports_table([
        {"port": 21, "service": "ftp", "version": "vsftpd 2.3.4", "cve_count": 1},
        {"port": 22, "service": "ssh", "version": "OpenSSH 4.7", "cve_count": 2},
    ])
    cve_table([
        (21, "ftp", 1, 10.0, "CVE-2011-2523"),
        (22, "ssh", 2, 6.5, "CVE-2016-0777, CVE-2018-15473"),
    ])
    exploits_table([
        {"cve": "CVE-2011-2523", "name": "vsftpd backdoor", "result": {"success": True}},
        {"cve": "CVE-2006-2369", "name": "VNC no-auth", "result": {"success": False}},
    ])
    cracked_table([("msfadmin", "msfadmin"), ("user", "user")])
    final_card("192.168.64.7", 18, 13, 1, 6, "reports/x.md", "reports/x.pdf", 252.4)
