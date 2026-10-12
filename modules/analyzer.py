# Analyzer — связь с LLM (Ollama)

import requests
import sys
import os
import time

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from config import OLLAMA_URL, MODELS, DEFAULT_MODEL, SYSTEM_PROMPT


def ask_llm(prompt, system=SYSTEM_PROMPT, model_key=None, max_retries=2):
    """Отправляет промпт в Ollama. Retry при ошибке."""
    
    if model_key is None:
        model_key = DEFAULT_MODEL
    
    model = MODELS.get(model_key, DEFAULT_MODEL)
    full_prompt = f"{system}\n\n{prompt}"
    
    for attempt in range(max_retries + 1):
        try:
            response = requests.post(
                OLLAMA_URL,
                json={
                    "model": model,
                    "prompt": full_prompt,
                    "stream": False,
                    "options": {"temperature": 0.3}
                },
                timeout=300
            )
            
            if response.status_code != 200:
                if attempt < max_retries:
                    time.sleep(2)
                    continue
                return f"Ошибка: {response.status_code}"
            
            data = response.json()
            return data.get("response", "Пустой ответ")
        
        except requests.Timeout:
            if attempt < max_retries:
                time.sleep(2)
                continue
            return "Timeout LLM"
        except requests.RequestException as e:
            if attempt < max_retries:
                time.sleep(2)
                continue
            return f"Ошибка Ollama: {e}"
    
    return "Не удалось получить ответ"


if __name__ == "__main__":
    print("Тест LLM...")
    print(ask_llm("Что такое SQLi? 1 предложение."))