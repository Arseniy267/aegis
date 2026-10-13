# modules/analyzer.py — связь с Ollama (v2: chat API + routing + logging)
"""
LLM interface to Ollama.

Uses /api/chat (system+user roles) instead of /api/generate (single prompt).
"""
from __future__ import annotations

import os
import sys
import time

import requests
import structlog

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from config import OLLAMA_CHAT_URL, MODELS, DEFAULT_MODEL, SYSTEM_PROMPT

log = structlog.get_logger("analyzer")

# --- derive chat endpoint -----------------------------------------------
# OLLAMA_URL пример: "http://localhost:11434/api/generate"
# Нам нужен:         "http://localhost:11434/api/chat"
if OLLAMA_URL.endswith("/api/generate"):
    OLLAMA_CHAT_URL = OLLAMA_URL[: -len("/api/generate")] + "/api/chat"
elif OLLAMA_URL.endswith("/api/chat"):
    OLLAMA_CHAT_URL = OLLAMA_URL
else:
    # на всякий случай
    OLLAMA_CHAT_URL = OLLAMA_URL.rstrip("/") + "/api/chat"

# --- routing table ------------------------------------------------------
_ROUTE = {
    "easy":   "fast",
    "normal": "fast",
    "hard":   "main",
}

# --- timeouts -----------------------------------------------------------
CONNECT_TIMEOUT = 10
READ_TIMEOUT = 180
MAX_RETRIES = 2
RETRY_SLEEP = 2


def _resolve_model(model_key: str | None, difficulty: str) -> str:
    """Выбор имени модели Ollama по ключу или сложности."""
    if model_key is None:
        model_key = _ROUTE.get(difficulty, DEFAULT_MODEL)

    # MODELS может содержать как "7b" → "qwen2.5:7b-instruct-q4_K_M",
    # так и напрямую имена
    if model_key in MODELS:
        return MODELS[model_key]
    if DEFAULT_MODEL in MODELS:
        return MODELS[DEFAULT_MODEL]
    return DEFAULT_MODEL  # последний резерв


def ask_llm(
    prompt: str,
    system: str = SYSTEM_PROMPT,
    model_key: str | None = None,
    max_retries: int = MAX_RETRIES,
    difficulty: str = "normal",
) -> str:
    """
    Отправляет prompt в Ollama /api/chat.

    Args:
        prompt: пользовательский запрос
        system: system-промпт (отдельное поле, не склейка)
        model_key: явный ключ модели из MODELS (приоритет над difficulty)
        max_retries: число повторов при сетевых ошибках
        difficulty: "easy" | "normal" | "hard" → 7B / 7B / 14B

    Returns:
        Строку с ответом или текстовое описание ошибки (никогда не бросает).
    """
    model = _resolve_model(model_key, difficulty)
    log.debug("llm_call_started", model=model, difficulty=difficulty,
              prompt_len=len(prompt), system_len=len(system))

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user",   "content": prompt},
        ],
        "stream": False,
        "options": {"temperature": 0.3},
    }

    t0 = time.time()
    last_err: str | None = None

    for attempt in range(max_retries + 1):
        try:
            r = requests.post(
                OLLAMA_CHAT_URL,
                json=payload,
                timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
            )

            if r.status_code == 200:
                data = r.json()
                # /api/chat возвращает {"message": {"role": "assistant", "content": "..."}}
                msg = data.get("message") or {}
                text = msg.get("content") or data.get("response") or "Пустой ответ"
                elapsed = round(time.time() - t0, 1)
                log.info("llm_call_done", model=model, elapsed_s=elapsed,
                         resp_len=len(text))
                return text

            # 5xx — стоит ретраить, 4xx — нет
            if 500 <= r.status_code < 600 and attempt < max_retries:
                last_err = f"HTTP {r.status_code}"
                log.warning("llm_call_retry", model=model,
                            status=r.status_code, attempt=attempt + 1)
                time.sleep(RETRY_SLEEP * (attempt + 1))
                continue

            last_err = f"HTTP {r.status_code}: {r.text[:200]}"
            log.error("llm_call_failed", model=model, status=r.status_code)
            return f"Ошибка: {r.status_code}"

        except requests.Timeout as e:
            last_err = f"Timeout: {e}"
            log.warning("llm_call_timeout", model=model,
                        attempt=attempt + 1, connect=CONNECT_TIMEOUT,
                        read=READ_TIMEOUT)
            if attempt < max_retries:
                time.sleep(RETRY_SLEEP * (attempt + 1))
                continue
            return "Timeout LLM"

        except requests.RequestException as e:
            last_err = f"RequestException: {e}"
            log.warning("llm_call_request_error", model=model,
                        err=str(e), attempt=attempt + 1)
            if attempt < max_retries:
                time.sleep(RETRY_SLEEP * (attempt + 1))
                continue
            return f"Ошибка Ollama: {e}"

    log.error("llm_call_exhausted", model=model, last_err=last_err)
    return f"Не удалось получить ответ: {last_err}"


# --- удобный async-обёртки для будущего --------------------------------
async def ask_llm_async(prompt: str, **kw) -> str:
    """Заглушка. Позже заменим на httpx.AsyncClient."""
    import asyncio
    return await asyncio.to_thread(ask_llm, prompt, **kw)


if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO,
                        format="%(levelname)-7s %(message)s")

    print("=== easy (7B) ===")
    print(ask_llm("Что такое SQLi? 1 предложение.", difficulty="easy")[:200])

    print("\n=== hard (14B) ===")
    print(ask_llm("Опиши вектор атаки на vsftpd 2.3.4 по шагам.", difficulty="hard")[:400])
