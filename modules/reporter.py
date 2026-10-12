# Reporter — Markdown + PDF через pandoc (v6: fix evidence return)

import os
import sys
import re
import subprocess
from datetime import datetime

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


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
    text = re.sub(r'[^\x20-\x7E\u0400-\u04FF\u2010-\u2030\n\t]', '', text)
    return text


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
        ids = re.findall(r"CVE-\d{4}-\d{4,}", text)
        top = ", ".join(sorted(set(ids))[:3])
        rows.append((port, svc, cnt, mx, top))
    return rows


def _evidence_section(data):
    """Секция доказательств взлома. Всегда возвращает строку."""
    parts = []
    ev = data.get("evidence") or {}

    parts.append("\\newpage\n")
    parts.append("# ДОКАЗАТЕЛЬСТВА ВЗЛОМА\n\n")

    if not ev:
        parts.append("_Эксплуатация не дала evidence._\n\n")
        return "".join(parts)

    parts.append("\\textcolor{evidencegreen}{\\textbf{Ниже — реальные команды, "
                 "выполненные на целевой машине через полученный root shell.}}\n\n")

    parts.append("## Соединение с целевой машиной\n\n")
    parts.append(f"**Target:** `{clean_text(ev.get('target', '—'))}`  \n")
    parts.append(f"**Shell:** `{clean_text(ev.get('shell', '—'))}`  \n")
    parts.append(f"**Время:** `{clean_text(ev.get('timestamp', '—'))}`  \n\n")

    commands = ev.get("commands") or []
    if commands:
        parts.append("## Выполненные команды\n\n")
        for label, cmd, out in commands:
            parts.append(f"### `{cmd}`\n\n")
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

    parts.append("\\newpage\n")
    parts.append("# IMPACT — Что злоумышленник мог бы сделать\n\n")
    parts.append("""Получив root-доступ и взломав учётные данные, злоумышленник мог бы:

1. **Войти по SSH как `msfadmin`** → полный интерактивный доступ к серверу
2. **Подключиться к MySQL как `root`** → чтение/изменение всей БД
3. **Использовать `sudo`** → выполнение любых команд
4. **Установить persistence** → сохранить доступ после перезагрузки
5. **Развернуть backdoor** → использовать как точку входа в сеть
6. **Украсть данные** → скопировать все конфиги, БД, ключи
7. **Pivot вглубь сети** → атаковать другие машины через эту

**Что нужно защитить:**
- Сменить все дефолтные пароли (msfadmin, root, service, user)
- Обновить vsftpd до 3.0.x (устраняет backdoor)
- Закрыть порт 6200 (backdoor shell)
- Заменить Telnet на SSH
- Настроить firewall
""")
    return "".join(parts)


def generate_report(target, recon_data, analysis, scripts_results=None, ports=None,
                    data=None, exploit_results=None):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    date_slug = datetime.now().strftime("%Y%m%d_%H%M%S")

    analysis = clean_text(analysis)
    nmap_compressed = clean_text(recon_data.get("nmap_compressed", "нет данных"))

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
\\textcolor{{aegisgray}}{{Версия: AEGIS Web v2.2}}
\\end{{center}}

\\vspace{{1cm}}

# 1. Разведка

## 1.1. Результаты nmap
{nmap_compressed}                                                               
# 2. Анализ (LLM)

{analysis if analysis else "нет данных"}

# 3. CVE по сервисам
"""

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

    report += "\n# 4. Эксплуатация уязвимостей\n\n"
    if exploit_results:
        for i, r in enumerate(exploit_results, 1):
            success = "УСПЕШНО" if r["result"]["success"] else "НЕ СРАБОТАЛО"
            report += f"## 4.{i}. {r['name']}\n\n"
            report += f"**CVE:** `{r['cve']}`  \n"
            report += f"**Порт:** {r['port']}  \n"
            report += f"**Версия:** `{clean_text(r.get('matched_version', ''))}`  \n"
            report += f"**Результат:** {success}\n\n"
            log = clean_text(r["result"].get("log", ""))
            report += f"```\n{log[:3000]}\n```\n\n"
    else:
        report += "_Эксплуатация не запускалась._\n\n"

    # Evidence
    has_evidence = (data and data.get("evidence") and 
                    data["evidence"].get("commands"))
    if has_evidence:
        report += _evidence_section(data)
    elif exploit_results:
        report += "\n# 5. Доказательства взлома\n\n"
        report += ("_Эксплуатация выполнена, но не дала root-доступа. "
                   "См. раздел 4 — все PoC отмечены как НЕ СРАБОТАЛО._\n\n")
    else:
        report += "\n# 5. Эксплуатация — не выполнялась\n\n"
        report += ("_В базе AEGIS нет готовых PoC для найденных CVE. "
                   "Все уязвимости требуют ручной проверки или специфических условий. "
                   "См. раздел 8 — рекомендации._\n\n")

    # Проверка сервисов
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

    # Сводка портов
    report += "\n# 7. Сводная таблица портов\n\n"
    if ports:
        report += "| Порт | Сервис | Версия |\n|------|--------|--------|\n"
        for p in ports:
            report += f"| {p['port']} | {clean_text(p['service'])} | {clean_text(p.get('version', ''))[:60]} |\n"
        report += "\n"
    else:
        report += "_Нет данных._\n\n"

    report += """# 8. Рекомендации по защите

1. Обновить уязвимые сервисы до последних версий.
2. Настроить firewall — закрыть неиспользуемые порты.
3. Установить fail2ban для защиты от брутфорса.
4. Заменить Telnet на SSH.
5. Сменить все дефолтные пароли.
6. Провести аудит конфигураций.

\\vspace{1cm}

\\begin{center}
\\textcolor{aegisgray}{\\small AEGIS Web v2.2 — Autonomous Exploitation \\& Guidance Intelligence System}\\\\
\\textcolor{aegisgray}{\\small Только для авторизованного пентеста.}
\\end{center}
"""

    os.makedirs("reports", exist_ok=True)

    header_path = os.path.join("reports", "aegis-header.tex")
    with open(header_path, "w") as f:
        f.write(LATEX_HEADER)

    md_path = f"reports/report_{date_slug}.md"
    with open(md_path, "w") as f:
        f.write(report)
    print(f"[+] Markdown: {md_path}")

    pdf_path = None
    try:
        pdf_path = f"reports/report_{date_slug}.pdf"
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
            capture_output=True, text=True, timeout=180
        )
        if result.returncode == 0 and os.path.exists(pdf_path):
            print(f"[+] PDF: {pdf_path}")
        else:
            print(f"[!] pandoc: {result.stderr[:500]}")
            pdf_path = None
    except FileNotFoundError:
        print("[!] pandoc не установлен")
    except Exception as e:
        print(f"[!] Ошибка PDF: {e}")

    return md_path, pdf_path
