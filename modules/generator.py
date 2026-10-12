# Generator — template-based генерация скриптов

import sys
import os
import re
from datetime import datetime

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from modules.analyzer import ask_llm


# Маппинг: сервис → шаблон
TEMPLATE_MAP = {
    "ftp": "ftp",
    "ssh": "ssh",
    "http": "http_check",
    "https": "http_check",
    "mysql": "mysql",
    "smb": "smb",
    "netbios-ssn": "smb",
    "microsoft-ds": "smb",
}

# Доступные шаблоны
TEMPLATES_DIR = os.path.join(_ROOT, "templates")


def detect_template(service):
    """Определяет шаблон по имени сервиса."""
    service_lower = service.lower()
    for key, template in TEMPLATE_MAP.items():
        if key in service_lower:
            return template
    return "generic"


def build_script_from_template(template_name, target, port):
    """Собирает скрипт из шаблона."""
    template_path = os.path.join(TEMPLATES_DIR, f"{template_name}.py")
    
    if not os.path.exists(template_path):
        template_path = os.path.join(TEMPLATES_DIR, "generic.py")
    
    with open(template_path) as f:
        code = f.read()
    
    return code


def generate_script(target, vulnerability_type, details="", port=None):
    """Генерирует скрипт на основе шаблона.
    
    vulnerability_type — имя сервиса (ftp, ssh, http, mysql, smb)
    port — номер порта
    """
    
    template_name = detect_template(vulnerability_type)
    print(f"[*] Шаблон: {template_name} (для {vulnerability_type})")
    
    # Если порт не указан — пытаемся угадать
    if port is None:
        port = _guess_port(vulnerability_type)
    
    # Собираем скрипт из шаблона
    script = build_script_from_template(template_name, target, port)
    
       # LLM доработка отключена (экономия RAM)
    # Используем только шаблон.
    
    # Сохраняем
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scripts/check_{template_name}_{port}_{timestamp}.py"
    
    os.makedirs("scripts", exist_ok=True)
    with open(filename, "w") as f:
        f.write(script)
    
    print(f"[+] Скрипт: {filename}")
    return filename


def _guess_port(service):
    """Угадывает порт по имени сервиса."""
    ports = {
        "ftp": 21,
        "ssh": 22,
        "telnet": 23,
        "smtp": 25,
        "dns": 53,
        "domain": 53,
        "http": 80,
        "https": 443,
        "smb": 445,
        "netbios-ssn": 139,
        "mysql": 3306,
        "postgresql": 5432,
        "vnc": 5900,
        "rpcbind": 111,
    }
    service_lower = service.lower()
    for key, port in ports.items():
        if key in service_lower:
            return port
    return 0


if __name__ == "__main__":
    print("=== Generator тест ===")
    
    for svc, port in [("ftp", 21), ("http", 80), ("ssh", 22)]:
        path = generate_script(
            target="192.168.64.7",
            vulnerability_type=svc,
            port=port
        )
        print(f"  → {path}\n")