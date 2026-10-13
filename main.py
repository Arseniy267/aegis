# main.py — AEGIS entrypoint (v6: whitelist on entry + logging + argparse)
"""
AEGIS — pentest orchestrator.

Usage:
    python main.py <target>                  # recon + report
    python main.py <target> --exploit        # + exploitation (needs whitelist)
    python main.py --multi                   # batch from targets.txt
    python main.py <target> --exploit --yes  # non-interactive
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
import time
import uuid
from pathlib import Path

# --- project root on sys.path ---
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import structlog
from rich.panel import Panel
from rich.prompt import Confirm, Prompt

from modules.console_ui import (
    console, banner, section, info, ok, warn, err, kv, step,
    ports_table, cve_table, exploits_table, cracked_table,
    final_card,
)
from modules.planner import full_analysis, full_analysis_multi, read_targets_file
from modules.reporter import generate_report
from modules.graph import ascii_graph, build_attack_graph, render_graph, HAS_GRAPH
from safety.whitelist import ensure_whitelisted, is_whitelisted, WhitelistError

# ----- constants ----------------------------------------------------------
LOG_DIR = _ROOT / "logs"
REPORT_DIR = _ROOT / "reports"
TARGETS_FILE = _ROOT / "targets.txt"
TOTAL_STEPS = 7

log = structlog.get_logger("aegis")


# ----- logging setup ------------------------------------------------------
def setup_logging(verbose: bool = False) -> str:
    LOG_DIR.mkdir(exist_ok=True)
    run_id = time.strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:6]
    log_path = LOG_DIR / f"aegis_{run_id}.log"

    level = logging.DEBUG if verbose else logging.INFO

    # stdlib handler → file
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
    ))
    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(file_handler)

    # structlog → stdlib (пишет и в файл, и в stderr через rich)
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # консольный обработчик для rich
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)   # в консоль только warnings+
    console_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    root.addHandler(console_handler)

    log.info("logging_initialized", run_id=run_id, log_path=str(log_path), verbose=verbose)
    return run_id


# ----- helpers ------------------------------------------------------------
def _cve_rows(data: dict) -> list[tuple]:
    import re
    rows = []
    cves = data.get("cves") or {}
    for p in data.get("ports", []):
        port = p["port"]
        svc = p.get("service", "?")
        cnt = p.get("cve_count", 0)
        mx = p.get("max_score", 0.0)
        if cnt == 0 and mx == 0:
            continue
        text = cves.get(port, "")
        ids = re.findall(r"CVE-\d{4}-\d{4,}", text)
        top = ", ".join(sorted(set(ids))[:2])
        rows.append((port, svc, cnt, mx, top))
    return rows


# ----- exploitation -------------------------------------------------------
def _run_exploitation(target: str, data: dict, auto_yes: bool) -> list:
    from modules.exploiter import run_all
    from modules.looter import loot_via_backdoor
    from modules.cracker import crack_text

    # уже проверяли в main(), но дублируем — функция может вызываться отдельно
    if not is_whitelisted(target):
        err(f"{target} не в whitelist — эксплуатация запрещена")
        log.warning("exploit_blocked_not_whitelisted", target=target)
        return []

    console.print()
    console.print(Panel.fit(
        "[bold red]ЭТАП ЭКСПЛУАТАЦИИ[/bold red]\n"
        "[dim]Будут запущены PoC для найденных CVE[/dim]",
        border_style="red", padding=(0, 2),
    ))

    if not auto_yes:
        if not Confirm.ask("[yellow]Продолжить эксплуатацию?[/yellow]", default=False):
            warn("Эксплуатация отменена пользователем")
            log.info("exploit_cancelled_by_user", target=target)
            return []

    log.info("exploit_started", target=target, ports=len(data.get("ports", [])))
    exploit_results = run_all(target, data["ports"], confirm=not auto_yes)
    exploits_table(exploit_results)

    n_ok = sum(1 for r in exploit_results if r["result"]["success"])
    log.info("exploit_finished", target=target, attempts=len(exploit_results), success=n_ok)

    vsftpd_ok = any(
        r["cve"] == "CVE-2011-2523" and r["result"]["success"]
        for r in exploit_results
    )
    if not vsftpd_ok:
        return exploit_results

    # --- Looter ---
    console.print()
    console.print(Panel.fit(
        "[bold red]ЭТАП СБОРА АРТЕФАКТОВ[/bold red]\n"
        "[dim]Получаем evidence + /etc/shadow через root shell[/dim]",
        border_style="red", padding=(0, 2),
    ))
    log.info("loot_started", target=target)
    loot = loot_via_backdoor(target)
    if not loot["success"]:
        err(f"Loot не удался: {loot['log'][:200]}")
        log.warning("loot_failed", target=target, error=loot["log"][:200])
        return exploit_results

    ok(f"Loot: {loot['output_dir']}")
    ok(f"id: {loot['id_out']}")
    log.info("loot_finished", target=target, output_dir=loot["output_dir"])

    data["evidence"] = loot.get("evidence", {})
    data["evidence"]["target"] = target

    # --- Cracker ---
    if loot.get("shadow_path") and os.path.exists(loot["shadow_path"]):
        with open(loot["shadow_path"]) as f:
            shadow_text = f.read()

        if shadow_text.strip():
            console.print()
            console.print(Panel.fit(
                "[bold green]ЭТАП ВЗЛОМА ХЕШЕЙ[/bold green]\n"
                "[dim]john по rockyou.txt[/dim]",
                border_style="green", padding=(0, 2),
            ))
            log.info("crack_started", target=target)
            crack_result = crack_text(
                shadow_text, loot["output_dir"], label="shadow", max_runtime=120,
            )
            if crack_result["cracked"]:
                cracked_table(crack_result["cracked"])
                data["cracked"] = crack_result["cracked"]
                data["loot_dir"] = loot["output_dir"]
                data["evidence"]["cracked"] = crack_result["cracked"]
                ok(f"Взломано: {len(crack_result['cracked'])}")
                log.info("crack_finished", target=target, cracked=len(crack_result["cracked"]))
            else:
                warn("Пароли не найдены")
                log.info("crack_no_hits", target=target)

    return exploit_results


# ----- single target ------------------------------------------------------
def run_one(target: str, *, do_exploit: bool = False, auto_yes: bool = False) -> dict:
    t0 = time.time()
    log.info("run_one_started", target=target, exploit=do_exploit)

    console.print(f"\n[bold cyan]Цель:[/bold cyan] [white]{target}[/white]\n")

    section(1, TOTAL_STEPS, "Разведка + анализ")
    data = full_analysis(target)
    ok(f"Анализ завершён. Портов: {len(data['ports'])}")
    log.info("recon_finished", target=target, ports=len(data["ports"]))

    ports_table(data["ports"])
    cve_table(_cve_rows(data))

    analysis = data.get("analysis", "")
    if analysis:
        preview = analysis[:1500] + ("..." if len(analysis) > 1500 else "")
        console.print()
        console.print(Panel(
            preview,
            title="[bold cyan]Анализ LLM[/bold cyan]",
            border_style="cyan", padding=(1, 2),
        ))

    if HAS_GRAPH:
        section(2, TOTAL_STEPS, "Граф атаки")
        console.print(ascii_graph(data["ports"][:10]))
        G = build_attack_graph(target, data["ports"])
        if G:
            path = render_graph(G)
            if path:
                ok(f"Граф: {path}")

    exploit_results: list = []
    if do_exploit:
        section(3, TOTAL_STEPS, "Эксплуатация")
        exploit_results = _run_exploitation(target, data, auto_yes=auto_yes)

    section(4, TOTAL_STEPS, "Отчёт")
    md_path, pdf_path = generate_report(
        target=target,
        recon_data={"nmap_compressed": data["nmap_compressed"]},
        analysis=analysis,
        scripts_results=None,
        ports=data["ports"],
        data=data,
        exploit_results=exploit_results,
    )
    ok(f"Markdown: {md_path}")
    if pdf_path:
        ok(f"PDF:      {pdf_path}")

    elapsed = time.time() - t0
    final_card(
        target=target,
        n_ports=len(data["ports"]),
        n_cve=sum(p.get("cve_count", 0) for p in data["ports"]),
        n_exploits=sum(1 for r in exploit_results if r["result"]["success"]),
        n_cracked=len(data.get("cracked", [])),
        md=md_path,
        pdf=pdf_path or "—",
        elapsed=elapsed,
    )
    log.info("run_one_finished", target=target, elapsed_s=round(elapsed, 1))

    return {
        "target": target,
        "md": md_path,
        "pdf": pdf_path,
        "elapsed": elapsed,
        "data": data,
    }


# ----- multi target -------------------------------------------------------
def run_multi(targets: list[str], *, max_workers: int = 1) -> dict:
    log.info("run_multi_started", n=len(targets), workers=max_workers)

    # фильтр whitelist
    safe = [t for t in targets if is_whitelisted(t)]
    skipped = sorted(set(targets) - set(safe))
    if skipped:
        warn(f"Пропущено (не в whitelist): {', '.join(skipped)}")
        log.warning("multi_skipped_not_whitelisted", skipped=skipped)
    if not safe:
        err("Ни одной цели в whitelist — выход")
        return {}

    console.print(f"\n[bold cyan]Multi-target:[/bold cyan] [white]{len(safe)} целей[/white]\n")

    all_data = full_analysis_multi(safe, max_workers=max_workers)
    results = {}
    for t, d in all_data.items():
        if d.get("error"):
            err(f"{t}: {d['error']}")
            log.error("multi_target_error", target=t, error=d["error"])
            continue
        console.print(f"\n[bold cyan]▸ {t}[/bold cyan]")
        ports_table(d["ports"][:10])
        if HAS_GRAPH:
            G = build_attack_graph(t, d["ports"])
            if G:
                out_png = REPORT_DIR / f"attack_graph_{t.replace('.', '_')}.png"
                path = render_graph(G, output_path=str(out_png))
                if path:
                    ok(f"Граф: {path}")
        md, pdf = generate_report(
            target=t,
            recon_data={"nmap_compressed": d["nmap_compressed"]},
            analysis=d.get("analysis", ""),
            scripts_results=None,
            ports=d["ports"],
            data=d,
            exploit_results=None,
        )
        ok(f"Отчёт: {md}")
        results[t] = {"md": md, "pdf": pdf}

    log.info("run_multi_finished", n_ok=len(results), n_skipped=len(skipped))
    return results


# ----- CLI ----------------------------------------------------------------
def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="aegis",
        description="AEGIS — autonomous pentest orchestrator",
    )
    p.add_argument("target", nargs="?", help="IP, hostname or URL")
    p.add_argument("--multi", action="store_true",
                   help="scan all targets from targets.txt")
    p.add_argument("--exploit", action="store_true",
                   help="enable exploitation stage (requires whitelist)")
    p.add_argument("--yes", "-y", action="store_true",
                   help="assume 'yes' for confirmation prompts")
    p.add_argument("--workers", type=int, default=1,
                   help="parallel workers for --multi (default 1 for 18 GB RAM)")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="debug logging")
    p.add_argument("--list-whitelist", action="store_true",
                   help="print loaded whitelist and exit")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])

    run_id = setup_logging(verbose=args.verbose)
    log.info("cli_started", argv=sys.argv, run_id=run_id)

    if args.list_whitelist:
        from safety.whitelist import _rules   # внутренний, но полезен для CLI
        print(f"Whitelist rules ({len(_rules())}):")
        for r in _rules():
            print(f"  [{r.kind:8}] {r.raw}")
        return 0

    # --- multi ---
    if args.multi:
        banner()
        targets = read_targets_file(str(TARGETS_FILE))
        if not targets:
            err(f"{TARGETS_FILE} пуст или не найден")
            log.warning("multi_no_targets", file=str(TARGETS_FILE))
            return 2
        try:
            run_multi(targets, max_workers=args.workers)
        except KeyboardInterrupt:
            console.print("\n[red]Прервано.[/red]")
            return 130
        except Exception as e:
            console.print(f"\n[red]Ошибка: {e}[/red]")
            log.exception("multi_unhandled")
            return 1
        return 0

    # --- single ---
    target = args.target
    if not target:
        banner()
        target = Prompt.ask("[yellow]Введите цель (IP или URL)[/yellow]")

    # whitelist ДО любых сетевых вызовов
    try:
        ensure_whitelisted(target)
    except WhitelistError as e:
        err(str(e))
        log.error("whitelist_rejected", target=target, error=str(e))
        return 1

    banner(target)

    try:
        run_one(target, do_exploit=args.exploit, auto_yes=args.yes)
    except KeyboardInterrupt:
        console.print("\n[red]Прервано.[/red]")
        log.warning("interrupted_by_user", target=target)
        return 130
    except WhitelistError as e:
        err(str(e))
        log.error("whitelist_error", target=target, error=str(e))
        return 1
    except Exception as e:
        console.print(f"\n[red]Ошибка: {e}[/red]")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
        log.exception("run_one_unhandled", target=target)
        return 1

    log.info("cli_finished", target=target, run_id=run_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
