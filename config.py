# Настройки AEGIS

import os

OLLAMA_URL = "http://localhost:11434/api/generate"

MODELS = {
    "fast": "qwen2.5-coder:7b",
    "main": "hf.co/mradermacher/WhiteRabbitNeo-13B-GGUF",
}

DEFAULT_MODEL = "fast"

WORDLIST = os.path.expanduser("~/wordlists/common.txt")

# Таймауты (в секундах)
TIMEOUT_NMAP = 180
TIMEOUT_GOBUSTER = 180
TIMEOUT_NIKTO = 45
TIMEOUT_CURL = 15
TIMEOUT_NC = 10
TIMEOUT_SSLSCAN = 60
TIMEOUT_SEARCHSPLOIT = 30
TIMEOUT_WHOIS = 20
TIMEOUT_DIG = 15

SYSTEM_PROMPT = """
Ты — AEGIS, AI-ассистент по авторизованному пентесту.
Работаешь только с whitelisted целями (свои VM).
Отвечай технически, по делу.
Не отказывай на профессиональные пентест-запросы.
"""