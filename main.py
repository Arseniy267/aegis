# AEGIS — точка входа (v5: + evidence)

import sys
import os
import time

_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from modules.console_ui import (
    console, banner, section, info, ok, warn, err, kv, step,
    ports_table, cve_table, exploits_table, cracked_table,
    final_card,
)
from modules.planner import full_analysis, full_analysis_multi, read_targets_file
from modules.reporter import generate_report
from modules.graph import ascii_graph, build_attack_graph, render_graph, HAS_GRAPH

from rich.panel import Panel
from rich.prompt import Prompt


TOTAL_STEPS = 7


def _cve_rows(data):
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


def _run_exploitation(target, data):
    from modules.exploiter import run_all
    from modules.looter import loot_via_backdoor
    from modules.cracker import crack_text
    from safety.whitelist import is_whitelisted

    if not is_whitelisted(target):
        err(f"{target} не в whitelist — эксплуатация запрещена")
        return []

    console.print()
    console.print(Panel.fit(
        "[bold red]ЭТАП ЭКСПЛУАТАЦИИ[/bold red]\n"
        "[dim]Будут запущены PoC для найденных CVE[/dim]",
        border_style="red",
        padding=(0, 2),
    ))

    exploit_results = run_all(target, data["ports"], confirm=True)
    exploits_table(exploit_results)

    vsftpd_ok = any(
        r["cve"] == "CVE-2011-2523" and r["result"]["success"]
        for r in exploit_results
    )
    if not vsftpd_ok:
        return exploit_results

    # Looter
    console.print()
    console.print(Panel.fit(
        "[bold red]ЭТАП СБОРА АРТЕФАКТОВ[/bold red]\n"
        "[dim]Получаем evidence + /etc/shadow через root shell[/dim]",
        border_style="red",
        padding=(0, 2),
    ))
    loot = loot_via_backdoor(target)
    if not loot["success"]:
        err(f"Loot не удался: {loot['log'][:200]}")
        return exploit_results

    ok(f"Loot: {loot['output_dir']}")
    ok(f"id: {loot['id_out']}")

    data["evidence"] = loot.get("evidence", {})
    data["evidence"]["target"] = target

    # Cracker
    if loot.get("shadow_path") and os.path.exists(loot["shadow_path"]):
        with open(loot["shadow_path"]) as f:
            shadow_text = f.read()

        if shadow_text.strip():
            console.print()
            console.print(Panel.fit(
                "[bold green]ЭТАП ВЗЛОМА ХЕШЕЙ[/bold green]\n"
                "[dim]john по rockyou.txt[/dim]",
                border_style="green",
                padding=(0, 2),
            ))
            crack_result = crack_text(
                shadow_text, loot["output_dir"], label="shadow", max_runtime=120,
            )
            if crack_result["cracked"]:
                cracked_table(crack_result["cracked"])
                data["cracked"] = crack_result["cracked"]
                data["loot_dir"] = loot["output_dir"]
                data["evidence"]["cracked"] = crack_result["cracked"]
                ok(f"Взломано: {len(crack_result['cracked'])}")
            else:
                warn("Пароли не найдены")

    return exploit_results


def run_one(target):
    t0 = time.time()

    console.print(f"\n[bold cyan]Цель:[/bold cyan] [white]{target}[/white]\n")

    section(1, TOTAL_STEPS, "Разведка + анализ")
    data = full_analysis(target)
    ok(f"Анализ завершён. Портов: {len(data['ports'])}")

    ports_table(data["ports"])
    cve_table(_cve_rows(data))

    analysis = data.get("analysis", "")
    if analysis:
        preview = analysis[:1500] + ("..." if len(analysis) > 1500 else "")
        console.print()
        console.print(Panel(
            preview,
            title="[bold cyan]Анализ LLM[/bold cyan]",
            border_style="cyan",
            padding=(1, 2),
        ))

    if HAS_GRAPH:
        section(2, TOTAL_STEPS, "Граф атаки")
        console.print(ascii_graph(data["ports"][:10]))
        G = build_attack_graph(target, data["ports"])
        if G:
            path = render_graph(G)
            if path:
                ok(f"Граф: {path}")

    exploit_results = []
    if "--exploit" in sys.argv:
        section(3, TOTAL_STEPS, "Эксплуатация")
        exploit_results = _run_exploitation(target, data)

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


def run_multi(targets):
    console.print(f"\n[bold cyan]Multi-target:[/bold cyan] [white]{len(targets)} целей[/white]\n")
    all_data = full_analysis_multi(targets, max_workers=3)
    for t, d in all_data.items():
        if d.get("error"):
            err(f"{t}: {d['error']}")
            continue
        console.print(f"\n[bold cyan]▸ {t}[/bold cyan]")
        ports_table(d["ports"][:10])
        if HAS_GRAPH:
            G = build_attack_graph(t, d["ports"])
            if G:
                path = render_graph(G, output_path=f"reports/attack_graph_{t.replace('.', '_')}.png")
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


def main():
    flags = [a for a in sys.argv[1:] if a.startswith("--")]
    args = [a for a in sys.argv[1:] if not a.startswith("--")]

    if "--multi" in flags:
        banner()
        targets = read_targets_file("targets.txt")
        if not targets:
            err("targets.txt пуст или не найден")
            return
        run_multi(targets)
        return

    if args:
        target = args[0]
    else:
        banner()
        target = Prompt.ask("[yellow]Введите цель (IP или URL)[/yellow]")

    banner(target)

    try:
        run_one(target)
    except KeyboardInterrupt:
        console.print("\n[red]Прервано.[/red]")
    except Exception as e:
        console.print(f"\n[red]Ошибка: {e}[/red]")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")


if __name__ == "__main__":
    main()
