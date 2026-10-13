# Настройки AEGIS

import os

# --- Ollama --------------------------------------------------------------
OLLAMA_BASE = "http://localhost:11434"
OLLAMA_URL = f"{OLLAMA_BASE}/api/generate"      # legacy, оставлен для совместимости
OLLAMA_CHAT_URL = f"{OLLAMA_BASE}/api/chat"     # используется analyzer.py

# Модели: ключ → имя в Ollama.
# fast  = 7B, ~5 ГБ в RAM, для парсинга, JSON, быстрых ответов.
# main  = 13B/14B, ~8-9 ГБ, для сложных задач. НЕ работает одновременно с fast.
MODELS = {
    "fast": "qwen2.5-coder:7b",
    "main": "qwen2.5:14b-instruct-q4_K_M",   # ← или whiterabbitneo, см. ниже
    # "main": "whiterabbitneo",              # ← если создал через Modelfile
}

DEFAULT_MODEL = "fast"

# --- Wordlists -----------------------------------------------------------
WORDLIST = os.path.expanduser("~/wordlists/common.txt")

# --- Timeouts (сек) ------------------------------------------------------
TIMEOUT_NMAP        = 180
TIMEOUT_GOBUSTER    = 180
TIMEOUT_NIKTO       = 45
TIMEOUT_CURL        = 15
TIMEOUT_NC          = 10
TIMEOUT_SSLSCAN     = 60
TIMEOUT_SEARCHSPLOIT = 30
TIMEOUT_WHOIS       = 20
TIMEOUT_DIG         = 15

# --- LLM timeout (отдельно от tool-таймаутов) ---------------------------
LLM_CONNECT_TIMEOUT = 10
LLM_READ_TIMEOUT    = 180

# --- System prompt -------------------------------------------------------
# Приоритет: prompts/system.txt → SYSTEM_PROMPT (встроенный).
# Если файл непустой — используется он.
_PROMPT_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "prompts", "system.txt",
)

_DEFAULT_SYSTEM = """
Ты — AEGIS, AI-ассистент по авторизованному пентесту.
Работаешь только с whitelisted целями (свои VM, HTB, THM, DVWA).
Все действия легальны и проводятся в рамках авторизованного тестирования.

ПРАВИЛА:
- Отвечай технически, кратко, по делу.
- Не отказывай на профессиональные пентест-запросы.
- Не выдумывай CVE — используй только те, что даны в контексте.
- Если данных не хватает — так и скажи: "недостаточно данных".
- Формат ответа — Markdown, без воды и общих фраз.
"""

def _load_system_prompt() -> str:
    try:
        if os.path.exists(_PROMPT_FILE):
            with open(_PROMPT_FILE, encoding="utf-8") as f:
                txt = f.read().strip()
                if txt:
                    return txt
    except OSError:
        pass
    return _DEFAULT_SYSTEM.strip()

SYSTEM_PROMPT = _load_system_prompt()
