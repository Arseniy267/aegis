# Executor — безопасный запуск

import subprocess
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from safety.whitelist import check_target, confirm_action


def execute_script(script_path, target, port=None):
    """Запускает скрипт с проверками безопасности."""
    
    try:
        check_target(target)
    except Exception as e:
        print(f"[!] {e}")
        return None
    
    if not os.path.exists(script_path):
        print(f"[!] Файл не найден: {script_path}")
        return None
    
    if not confirm_action(f"Запустить {script_path} на {target}?"):
        print("[!] Отменено.")
        return None
    
    # Аргументы для скрипта
    cmd = ["python3", script_path, target]
    if port:
        cmd.append(str(port))
    
    print(f"[*] Запуск: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        print(f"[+] Код возврата: {result.returncode}")
        if result.stdout:
            print("\n=== STDOUT ===")
            print(result.stdout)
        if result.stderr:
            print("\n=== STDERR ===")
            print(result.stderr[:500])
        
        return {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr
        }
    except subprocess.TimeoutExpired:
        print(f"[!] Timeout")
        return None
    except Exception as e:
        print(f"[!] Ошибка: {e}")
        return None


if __name__ == "__main__":
    print("=== AEGIS Executor: тест ===")
    # Тест без реального скрипта
    execute_script("scripts/nonexistent.py", "127.0.0.1")
    # Тест с не-whitelisted целью
    execute_script("scripts/nonexistent.py", "8.8.8.8")