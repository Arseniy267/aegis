# Agent — автономный цикл AEGIS

import sys
import os
import json
import re

# СНАЧАЛА добавляем корень проекта в sys.path
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

# ТОЛЬКО ПОТОМ импортируем модули
from modules.analyzer import ask_llm
from modules.recon import (
    run_nmap, run_gobuster, run_curl, run_nc,
    run_dig, run_whois, run_searchsploit,
    run_sslscan, run_nikto, compress_nmap_output
)
from modules.rag import get_cve_context

TOOLS = {
    "nmap": {
        "description": "Сканирует порты и сервисы. Аргумент: target",
        "args": ["target"],
        "func": lambda target: compress_nmap_output(run_nmap(target))
    },
    "nmap_script": {
        "description": "nmap со скриптами. Аргументы: target, scripts",
        "args": ["target", "scripts"],
        "func": lambda target, scripts: run_nmap(target, scripts)
    },
    "gobuster": {
        "description": "Ищет директории ТОЛЬКО на HTTP/HTTPS. Аргумент: url",
        "args": ["url"],
        "func": lambda url: run_gobuster(url)
    },
    "curl": {
        "description": "HTTP-заголовки. Аргумент: url",
        "args": ["url"],
        "func": lambda url: run_curl(url)
    },
    "nc": {
        "description": "Баннер порта. Аргументы: host, port",
        "args": ["host", "port"],
        "func": lambda host, port: run_nc(host, port)
    },
    "dig": {
        "description": "DNS-информация. Аргумент: domain",
        "args": ["domain"],
        "func": lambda domain: run_dig(domain)
    },
    "whois": {
        "description": "Инфо о домене. Аргумент: domain",
        "args": ["domain"],
        "func": lambda domain: run_whois(domain)
    },
    "searchsploit": {
        "description": "CVE в ExploitDB. Аргумент: query",
        "args": ["query"],
        "func": lambda query: run_searchsploit(query)
    },
    "sslscan": {
        "description": "SSL/TLS. Аргументы: host, port",
        "args": ["host", "port"],
        "func": lambda host, port=443: run_sslscan(host, port)
    },
    "nikto": {
        "description": "Уязвимости ВЕБ-СЕРВЕРА. Аргумент: url",
        "args": ["url"],
        "func": lambda url: run_nikto(url)
    },
    "finish": {
        "description": "Завершить. Аргумент: summary",
        "args": ["summary"],
        "func": lambda summary: summary

        
    },

        "search_cve": {
        "description": "Ищет CVE для сервиса через NVD. Аргументы: service, version (опционально)",
        "args": ["service"],
        "func": lambda service: get_cve_context(service)
    },
}


def format_tools():
    lines = []
    for name, info in TOOLS.items():
        args = ", ".join(info["args"])
        lines.append(f"- {name}({args}): {info['description']}")
    return "\n".join(lines)


def parse_llm_json(response):
    match = re.search(r"\{[\s\S]*\}", response)
    if not match:
        return None
    try:
        return json.loads(match.group(0))
    except json.JSONDecodeError:
        return None


def agent_step(target, history, step_num):
    tools_desc = format_tools()
    history_str = "\n".join([f"Шаг {i+1}: {h}" for i, h in enumerate(history)]) or "пока пусто"
    
    prompt = f"""Ты — AEGIS, автономный AI-агент для авторизованного пентеста.

ЦЕЛЬ: Проанализировать {target} и найти потенциальные уязвимости.

ИСТОРИЯ ШАГОВ:
{history_str}

ДОСТУПНЫЕ ИНСТРУМЕНТЫ:
{tools_desc}

ЖЁСТКИЕ ПРАВИЛА:
1. Используй ТОЛЬКО указанные аргументы.
2. НЕ повторяй инструмент с теми же аргументами.
3. Если инструмент вернул "нет вывода"/"timeout"/"ошибка" — попробуй ДРУГОЙ.
4. gobuster/nikto работают ТОЛЬКО с HTTP/HTTPS (не RTSP, не SSH).
5. Если сервис не HTTP — используй nmap, nc, searchsploit.
6. Если собрал 3+ результата — завершай (finish).
7. Максимум 8 шагов.
8. ПЕРЕД анализом уязвимостей — используй search_cve для найденных сервисов.
   Например: search_cve(service="Apache", version="2.4")

ОТВЕЧАЙ ТОЛЬКО JSON:
{{
  "thought": "рассуждения",
  "action": "инструмент",
  "args": {{"target": "{target}"}},
  "done": false
}}

Завершение: action="finish", done=true, args={{"summary": "итог"}}.

Твой шаг (ТОЛЬКО JSON, без markdown):"""
    
    response = ask_llm(prompt)
    print(f"\n[LLM] {response[:200]}...")
    
    return parse_llm_json(response)


def run_agent(target, max_steps=8):
    print(f"\n{'='*60}")
    print(f"AGENT LOOP — цель: {target}")
    print(f"{'='*60}\n")
    
    history = []
    used_actions = []
    
    for step in range(max_steps):
        print(f"\n--- Шаг {step + 1} ---")
        
        decision = agent_step(target, history, step)
        if not decision:
            print("[!] JSON не распарсен")
            break
        
        thought = decision.get("thought", "...")
        action = decision.get("action", "")
        args = decision.get("args", {})
        done = decision.get("done", False)
        
        print(f"[Мысль] {thought}")
        print(f"[Действие] {action}({args})")
        
        if done or action == "finish":
            summary = args.get("summary", "Завершено")
            print(f"\n[✓] {summary}")
            history.append(f"ФИНАЛ: {summary}")
            break
        
        action_sig = f"{action}:{json.dumps(args, sort_keys=True)}"
        if action_sig in used_actions:
            print(f"[!] Повтор — пропускаю")
            history.append(f"{action} → ПОВТОР")
            continue
        used_actions.append(action_sig)
        
        if action in TOOLS:
            try:
                result = TOOLS[action]["func"](**args)
                preview = str(result)[:500]
                print(f"[Результат] {preview}")
                
                fail_signals = ["не найден", "ошибка", "error", "timeout", "не найдено"]
                if any(s in preview.lower() for s in fail_signals):
                    history.append(f"{action}({args}) → FAILED: {preview[:150]}")
                else:
                    history.append(f"{action}({args}) → {preview}")
            except TypeError as e:
                print(f"[!] Аргументы: {e}")
                history.append(f"{action} → FAILED: неверные аргументы")
            except Exception as e:
                print(f"[!] Ошибка: {e}")
                history.append(f"{action} → FAILED: {e}")
        else:
            print(f"[!] Неизвестный: {action}")
            history.append(f"НЕИЗВЕСТНЫЙ: {action}")
    
    print(f"\n{'='*60}")
    print(f"AGENT LOOP завершён: {len(history)} шагов")
    print(f"{'='*60}\n")
    return history


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    run_agent(target, max_steps=8)