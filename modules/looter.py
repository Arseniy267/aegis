# modules/reporter.py — Markdown + PDF через pandoc (v6.1 fixed)

import os
import re
import structlog
import subprocess
import sys
from datetime import datetime

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

REPORT_DIR = os.path.join(_ROOT, "reports")

log = structlog.get_logger("reporter")


LATEX_HEADER = r"""
\usepackage{xcolor}
\usepackage{titlesec}
\usepackage{fancyhdr}
\usepackage{graphicx}
\usepackage{booktabs}
\definecolor{aegisred}{HTML}{CC0000}
\definecolor{aegiscyan}{HTML}{0099CC}
\definecolor{aegisgray}{HTML}{666666}
\definecolor{evidencegreen}{HTML}{008844}
\titleformat{\section}{\color{aegisred}\Large\bfseries}{\thesection}{1em}{}
\titleformat{\subsection}{\color{aegiscyan}\large\bfseries}{\thesubsection}{1em}{}
\titleformat{\subsubsection}{\color{aegisgray}\normalsize\bfseries}{\thesubsubsection}{1em}{}
\pagestyle{fancy}
\fancyhf{}
\fancyhead[L]{\textcolor{aegisgray}{AEGIS Report}}
\fancyhead[R]{\textcolor{aegisgray}{\thepage}}
\renewcommand{\headrulewidth}{0.4pt}
"""


def clean_text(text):
    if not text:
        return ""
    return re.sub(
        r'[^\x20-\x7E\u0400-\u04FF\u2000-\u206F\u2190-\u21FF\u2600-\u27BF\n\t]',
        '', text
    )


def _cve_rows(data):
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
        pairs = []
        for line in text.splitlines():
            m_id = re.search(r"CVE-\d{4}-\d{4,}", line)
            m_sc = re.search(r"CVSS:\s*([\d.]+)", line)
            if m_id:
                sc = float(m_sc.group(1)) if m_sc else 0.0
                pairs.append((m_id.group(0), sc))

        pairs.sort(key=lambda x: -x[1])
        seen = set()
        top_ids = []
        for cid, _ in pairs:
            if cid not in seen:
                seen.add(cid)
                top_ids.append(cid)
            if len(top_ids) == 3:
                break

        top = ", ".join(top_ids)
        rows.append((port, svc, cnt, mx, top))
    return rows


def _evidence_section(data):
    """Только ДОКАЗАТЕЛЬСТВА: shell, команды, shadow, cracked creds."""
    ev = data.get("evidence") or {}
    if not ev:
        return ""

    parts = []
    parts.append("\\newpage\n")
    parts.append("# ДОКАЗАТЕЛЬСТВА ВЗЛОМА\n\n")
    parts.append("\\textcolor{evidencegreen}{\\textbf{Ниже — реальные команды, "
                 "выполненные на целевой машине через полученный root shell.}}\n\n")

    parts.append("## Соединение с целевой машиной\n\n")
    parts.append(f"**Target:** `{clean_text(ev.get('target', '—'))}`  \n")
    parts.append(f"**Shell:** `{clean_text(ev.get('shell', '—'))}`  \n")
    if ev.get("id_out"):
        parts.append(f"**Identity:** `{clean_text(ev['id_out'])}`  \n")
    parts.append(f"**Время:** `{clean_text(ev.get('timestamp', '—'))}`  \n\n")

    commands = ev.get("commands") or []
    if commands:
        parts.append("## Выполненные команды\n\n")
        for entry in commands:
            if len(entry) == 3:
                _label, cmd, out = entry
            elif len(entry) == 2:
                cmd, out = entry
            else:
                continue
            parts.append(f"### `{clean_text(cmd)}`\n\n")
            parts.append("```\n")
            parts.append(clean_text(out)[:1000])
            parts.append("\n```\n\n")

    if ev.get("shadow_head"):
        parts.append("## Содержимое /etc/shadow (первые строки)\n\n")
        parts.append("```\n")
        parts.append(clean_text(ev["shadow_head"])[:800])
        parts.append("\n```\n\n")

    if ev.get("cracked"):
        parts.append("## Взломанные учётные данные\n\n")
        parts.append("\\textcolor{aegisred}{\\textbf{КРИТИЧНО:}}\n\n")
        parts.append("| Пользователь | Пароль |\n|--------------|--------|\n")
        for u, p in ev["cracked"]:
            parts.append(f"| `{clean_text(u)}` | `{clean_text(p)}` |\n")
        parts.append("\n")

    return "".join(parts)


def _risk_summary(data):
    ports = data.get("ports") or []
    if not ports:
        return ""
    crit = sum(1 for p in ports if p.get("max_score", 0) >= 9)
    high = sum(1 for p in ports if 7 <= p.get("max_score", 0) < 9)
    med  = sum(1 for p in ports if 4 <= p.get("max_score", 0) < 7)
    low  = sum(1 for p in ports if 0 < p.get("max_score", 0) < 4)

    return (
        "\n## Сводка по критичности\n\n"
        "| Уровень | Портов |\n|---|---|\n"
        f"| CRIT (>=9.0) | {crit} |\n"
        f"| HIGH (7.0-8.9) | {high} |\n"
        f"| MED (4.0-6.9) | {med} |\n"
        f"| LOW (<4.0) | {low} |\n\n"
    )


def _impact_section(data, exploit_results=None):
    """IMPACT — из реальных находок, без хардкодов."""
    ev = data.get("evidence") or {}
    cracked = ev.get("cracked") or []
    ports = data.get("ports") or []
    exploit_results = exploit_results or []

    parts = []
    parts.append("\\newpage\n")
    parts.append("# IMPACT — Что злоумышленник мог бы сделать\n\n")

    id_out = (ev.get("id_out") or "").strip()
    is_root = "uid=0" in id_out or id_out.lower().startswith("root")

    if is_root:
        parts.append("Получен **root-доступ** через эксплуатацию:\n\n")
    elif id_out:
        parts.append(f"Получен доступ уровня пользователя "
                     f"(`{clean_text(id_out[:60])}`):\n\n")
    else:
        parts.append("Эксплуатация дала доступ к системе:\n\n")

    successful = [r for r in exploit_results
                  if r.get("result", {}).get("success")]
    for r in successful:
        parts.append(f"- `{r.get('cve', '?')}` — "
                     f"{clean_text(r.get('name', '?'))} "
                     f"(порт {r.get('port', '?')})\n")
    parts.append("\n")

    if cracked:
        parts.append("Взломаны учётные данные:\n\n")
        parts.append("| Пользователь | Пароль |\n|---|---|\n")
        for u, p in cracked:
            parts.append(f"| `{clean_text(u)}` | `{clean_text(p)}` |\n")
        parts.append("\n")
        parts.append("Это позволяет злоумышленнику:\n\n")
        parts.append("- Войти по SSH/SMB/иным протоколам с валидными кредами\n")
        parts.append("- Использовать `sudo` там, где разрешено\n")
        parts.append("- Установить persistence и сохранить доступ\n")
        parts.append("- Провести lateral movement вглубь сети\n\n")
    else:
        parts.append("Доступ к системе позволяет злоумышленнику:\n\n")
        parts.append("- Выполнять команды от имени полученного пользователя\n")
        parts.append("- Читать файлы конфигурации, БД и ключи\n")
        parts.append("- Использовать эту машину как точку pivot во внутреннюю сеть\n\n")

    open_ports = {p["port"] for p in ports}
    svcs = {p.get("service", "").lower() for p in ports}

    recs = []
    if 6200 in open_ports:
        recs.append("Закрыть порт 6200 (vsftpd backdoor shell)")
    if 21 in open_ports or "ftp" in svcs:
        recs.append("FTP: обновить сервер, отключить anonymous-доступ, "
                    "перейти на SFTP/FTPS")
    if 22 in open_ports or "ssh" in svcs:
        recs.append("SSH: отключить парольную аутентификацию, перейти на ключи")
    if 23 in open_ports or "telnet" in svcs:
        recs.append("Telnet: заменить на SSH")
    if {139, 445} & open_ports or "smb" in svcs:
        recs.append("SMB: отключить SMBv1, закрыть 445/139 на периметре")
    if 3306 in open_ports or "mysql" in svcs:
        recs.append("MySQL: bind на 127.0.0.1, сменить root-пароль")
    if 3389 in open_ports:
        recs.append("RDP: включить NLA, ограничить по IP")
    if 6379 in open_ports or "redis" in svcs:
        recs.append("Redis: обязательно пароль + bind на localhost")
    if {80, 443, 8080, 8443} & open_ports:
        recs.append("Web: закрыть admin-панели по IP-whitelist, "
                    "обновить серверы")

    recs.append("Сменить все дефолтные пароли")
    recs.append("Настроить firewall — закрыть неиспользуемые порты")

    if recs:
        parts.append("**Что нужно исправить:**\n\n")
        for i, r in enumerate(recs, 1):
            parts.append(f"{i}. {r}\n")
        parts.append("\n")

    return "".join(parts)


def _recommendations(data, ports):
    """Рекомендации на основе реальных портов. Без хардкодов."""
    ports = ports or []
    open_ports = {p["port"] for p in ports}
    svcs = {p.get("service", "").lower() for p in ports}

    recs = ["Обновить все устаревшие сервисы до актуальных версий."]

    if 21 in open_ports or "ftp" in svcs:
        recs.append("FTP: отключить anonymous, обновить сервер, перейти на FTPS/SFTP.")
    if 22 in open_ports or "ssh" in svcs:
        recs.append("SSH: отключить пароли, использовать ключи, ограничить по IP.")
    if 23 in open_ports or "telnet" in svcs:
        recs.append("Telnet: заменить на SSH — трафик в открытом виде.")
    if {80, 443, 8080, 8443} & open_ports:
        recs.append("Web: закрыть admin-панели по IP-whitelist, "
                    "включить WAF, проверить TLS.")
    if {139, 445} & open_ports or "smb" in svcs:
        recs.append("SMB: отключить SMBv1, заблокировать 445/139 на периметре.")
    if 3306 in open_ports or "mysql" in svcs:
        recs.append("MySQL: bind на 127.0.0.1, сменить root-пароль.")
    if 3389 in open_ports:
        recs.append("RDP: включить NLA, ограничить по IP, включить MFA.")
    if 6379 in open_ports or "redis" in svcs:
        recs.append("Redis: пароль + bind на localhost, никаких открытых инстансов.")

    recs.append("Firewall: закрыть всё, кроме действительно нужных портов.")
    recs.append("Настроить логирование и алерты на подозрительную активность.")

    return "\n".join(f"{i+1}. {r}" for i, r in enumerate(recs))


def generate_report(target, recon_data, analysis, scripts_results=None, ports=None,
                    data=None, exploit_results=None):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    date_slug = datetime.now().strftime("%Y%m%d_%H%M%S")
    skip_pdf = os.environ.get("AEGIS_NO_PDF", "0") == "1"

    analysis = clean_text(analysis)
    nmap_compressed = clean_text(recon_data.get("nmap_compressed", "нет данных"))

    # ─── Шапка + секции 1-3 (f-string ЗАКРЫВАЕТСЯ после "# 3. CVE по сервисам") ───
    report = f"""---
title: "AEGIS Report — {target}"
date: "{timestamp}"
toc: true
toc-title: "Содержание"
---

\\begin{{center}}
\\textcolor{{aegisred}}{{\\Huge\\bfseries AEGIS Report}}\\\\[0.3cm]
\\textcolor{{aegisgray}}{{\\large Autonomous Exploitation \\& Guidance Intelligence System}}\\\\[0.5cm]
\\textcolor{{aegiscyan}}{{\\Large Цель: {target}}}\\\\[0.2cm]
\\textcolor{{aegisgray}}{{Дата: {timestamp}}}\\\\[0.2cm]
\\textcolor{{aegisgray}}{{Версия: AEGIS Web v2.3}}
\\end{{center}}

\\vspace{{1cm}}

# 1. Разведка

## 1.1. Результаты nmap
{nmap_compressed}

# 2. Анализ (LLM)

{analysis if analysis else "нет данных"}

# 3. CVE по сервисам
"""

    # ─── Секция 3: CVE-таблица ───
    if data:
        rows = _cve_rows(data)
        if rows:
            report += "\n| Порт | Сервис | CVE | Max CVSS | Топ CVE |\n"
            report += "|------|--------|-----|----------|---------|\n"
            for port, svc, cnt, mx, top in rows:
                if mx >= 9:
                    sev = "CRIT"
                elif mx >= 7:
                    sev = "HIGH"
                elif mx >= 4:
                    sev = "MED"
                else:
                    sev = "LOW"
                report += f"| {port} | {svc} | {cnt} | {sev} {mx} | {top} |\n"
            report += "\n"
        else:
            report += "\n_Нет данных._\n"
    else:
        report += "\n_Нет данных._\n"

    # ─── Секция 4: Эксплуатация ───
    report += "\n# 4. Эксплуатация уязвимостей\n\n"
    if exploit_results:
        for i, r in enumerate(exploit_results, 1):
            success = "УСПЕШНО" if r["result"]["success"] else "НЕ СРАБОТАЛО"
            report += f"## 4.{i}. {r['name']}\n\n"
            report += f"**CVE:** `{r['cve']}`  \n"
            report += f"**Порт:** {r['port']}  \n"
            report += f"**Версия:** `{clean_text(r.get('matched_version', ''))}`  \n"
            report += f"**Результат:** {success}\n\n"
            log_text = clean_text(r["result"].get("log", ""))
            report += f"```\n{log_text[:3000]}\n```\n\n"
    else:
        report += "_Эксплуатация не запускалась._\n\n"

    # ─── Секция 5: Evidence + IMPACT ───
    has_evidence = (data and data.get("evidence")
                    and data["evidence"].get("commands"))
    if has_evidence:
        report += _evidence_section(data)
        report += _impact_section(data, exploit_results)
    elif exploit_results:
        report += "\n\\newpage\n# 5. Доказательства взлома\n\n"
        report += ("_Эксплуатация выполнена, но не дала root-доступа. "
                   "См. раздел 4 — все PoC отмечены как НЕ СРАБОТАЛО._\n\n")
    else:
        report += "\n\\newpage\n# 5. Эксплуатация — не выполнялась\n\n"
        report += ("_В базе AEGIS нет готовых PoC для найденных CVE. "
                   "Все уязвимости требуют ручной проверки._\n\n")

    # ─── Секция 6: Проверка сервисов ───
    report += "\n# 6. Проверка сервисов\n\n"
    if scripts_results:
        for i, info in enumerate(scripts_results, 1):
            port = info.get("port")
            service = info.get("service")
            result = info.get("result") or {}
            report += f"## 6.{i}. {service} (порт {port})\n\n"
            if result:
                stdout = clean_text(result.get("stdout") or "").strip()
                if stdout:
                    report += f"```\n{stdout[:1500]}\n```\n\n"
    else:
        report += "_Скрипты не генерировались._\n\n"

    # ─── Секция 7: Сводка портов ───
    report += "\n# 7. Сводная таблица портов\n\n"
    if ports:
        report += "| Порт | Сервис | Версия |\n|------|--------|--------|\n"
        for p in ports:
            report += (f"| {p['port']} | {clean_text(p['service'])} | "
                       f"{clean_text(p.get('version', ''))[:60]} |\n")
        report += "\n"
    else:
        report += "_Нет данных._\n\n"

    # ─── Секция 8: Рекомендации ───
    report += "# 8. Рекомендации по защите\n\n"
    report += _recommendations(data, ports) + "\n\n"

    # ─── Футер ───
    report += (
        "\\vspace{1cm}\n\n"
        "\\begin{center}\n"
        "\\textcolor{aegisgray}{\\small AEGIS Web v2.3 — "
        "Autonomous Exploitation \\& Guidance Intelligence System}\\\\\n"
        "\\textcolor{aegisgray}{\\small Только для авторизованного пентеста.}\n"
        "\\end{center}\n"
    )

    # ─── Запись файлов ───
    os.makedirs(REPORT_DIR, exist_ok=True)

    header_path = os.path.join(REPORT_DIR, "aegis-header.tex")
    with open(header_path, "w", encoding="utf-8") as f:
        f.write(LATEX_HEADER)

    md_path = os.path.join(REPORT_DIR, f"report_{date_slug}.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(report)
    log.info("report_markdown_written", path=md_path)

    # ─── PDF (опционально) ───
    if skip_pdf:
        log.info("pdf_skipped_by_env")
        return md_path, None

    pdf_path = None
    try:
        pdf_path = os.path.join(REPORT_DIR, f"report_{date_slug}.pdf")
        result = subprocess.run(
            ["pandoc", md_path, "-o", pdf_path,
             "--pdf-engine=xelatex",
             "--toc", "--number-sections",
             f"--include-in-header={header_path}",
             "-V", "mainfont=Helvetica",
             "-V", "monofont=Menlo",
             "-V", "lang=ru",
             "-V", "geometry:margin=2cm",
             "-V", "colorlinks=true",
             "-V", "linkcolor=aegiscyan",
             "-V", "toccolor=aegisred"],
            capture_output=True, text=True, timeout=180,
        )
        if result.returncode == 0 and os.path.exists(pdf_path):
            log.info("report_pdf_written", path=pdf_path)
        else:
            log.warning("pandoc_failed", stderr=result.stderr[:500])
            pdf_path = None
    except FileNotFoundError:
        log.warning("pandoc_not_installed")
        pdf_path = None                # ← добавить эту строку
    except Exception as e:
        log.error("pdf_render_failed", err=str(e))
        pdf_path = None

    return md_path, pdf_path
