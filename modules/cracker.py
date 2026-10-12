# Cracker — john / hashcat обёртка для взлома хешей

import os
import re
import subprocess
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


WORDLIST_FAST = os.path.join(_ROOT, "wordlists", "top10k.txt")
WORDLIST_ROCKYOU = os.path.join(_ROOT, "wordlists", "rockyou.txt")
WORDLIST_HEAVY = WORDLIST_ROCKYOU


def _pick_wordlist(prefer_heavy=False):
    candidates = [
        WORDLIST_ROCKYOU if prefer_heavy else WORDLIST_FAST,
        WORDLIST_FAST,
        WORDLIST_ROCKYOU,
    ]
    for c in candidates:
        if os.path.exists(c) and os.path.getsize(c) > 1000:
            return c
    return WORDLIST_FAST


def _run(cmd, timeout=180, input_text=None):
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            input=input_text,
        )
        return r.stdout + "\n" + r.stderr
    except subprocess.TimeoutExpired:
        return f"[timeout {timeout}s]"
    except FileNotFoundError:
        return f"[не найдено: {cmd[0]}]"
    except Exception as e:
        return f"[ошибка: {e}]"


def detect_hash_type(hash_line):
    h = hash_line.strip()
    if not h:
        return None
    if ":" in h and h.split(":", 1)[1].startswith("$"):
        h = h.split(":", 1)[1]
    if h.startswith("$1$"):
        return "md5crypt"
    if h.startswith("$5$"):
        return "sha256crypt"
    if h.startswith("$6$"):
        return "sha512crypt"
    if h.startswith("$2"):
        return "bcrypt"
    if h.startswith("$y$"):
        return "yescrypt"
    if re.match(r"^[a-fA-F0-9]{32}$", h):
        return "raw-md5"
    if re.match(r"^[a-fA-F0-9]{40}$", h):
        return "raw-sha1"
    if re.match(r"^[a-fA-F0-9]{64}$", h):
        return "raw-sha256"
    return None


def extract_hashes_from_text(text):
    hashes = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^([^:]+):(\$[^:]+):", line)
        if m:
            hashes.append(f"{m.group(1)}:{m.group(2)}")
            continue
        parts = line.split(":")
        if len(parts) >= 2 and parts[1].startswith("$"):
            hashes.append(f"{parts[0]}:{parts[1]}")
            continue
        m = re.match(r"^([^:]+):\d+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}:::", line)
        if m:
            hashes.append(line)
            continue
    return hashes


def save_hash_file(hashes, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write("\n".join(hashes))
    return path


def run_john(hash_file, wordlist=None, hash_format=None, timeout=180, max_runtime=None):
    if wordlist is None:
        wordlist = _pick_wordlist()
    if not os.path.exists(hash_file):
        return f"[файл хешей не найден: {hash_file}]", []
    if not os.path.exists(wordlist):
        return f"[словарь не найден: {wordlist}]", []

    pot = os.path.expanduser("~/.john/john.pot")
    if os.path.exists(pot):
        try:
            os.remove(pot)
        except Exception:
            pass

    cmd = ["john", f"--wordlist={wordlist}"]
    if hash_format:
        cmd.append(f"--format={hash_format}")
    cmd.append(hash_file)

    size_kb = os.path.getsize(wordlist) // 1024
    print(f"    [john] словарь: {os.path.basename(wordlist)} ({size_kb} KB)")
    if max_runtime:
        print(f"    [john] лимит времени: {max_runtime}s")

    out = _run(cmd, timeout=max_runtime or timeout)

    show_cmd = ["john", "--show"]
    if hash_format:
        show_cmd.append(f"--format={hash_format}")
    show_cmd.append(hash_file)
    show_out = _run(show_cmd, timeout=30)

    cracked = _parse_john_show(show_out)
    return out + "\n" + show_out, cracked


def _parse_john_show(show_out):
    results = []
    for line in show_out.splitlines():
        if ":" not in line:
            continue
        if "password hash cracked" in line.lower():
            continue
        if line.startswith("---"):
            continue
        parts = line.split(":")
        if len(parts) >= 2:
            user = parts[0].strip()
            pw = parts[1].strip()
            if pw and not pw.startswith("$"):
                results.append((user, pw))
    return results


JOHN_TO_HASHCAT = {
    "md5crypt": 500, "sha256crypt": 7400, "sha512crypt": 1800,
    "bcrypt": 3200, "raw-md5": 0, "raw-sha1": 100,
    "raw-sha256": 1400, "nt": 1000, "netntlmv2": 5600,
}


def run_hashcat(hash_file, hash_format="md5crypt", wordlist=None, timeout=180):
    if wordlist is None:
        wordlist = _pick_wordlist()
    if not os.path.exists(hash_file):
        return f"[файл хешей не найден: {hash_file}]", []
    if not os.path.exists(wordlist):
        return f"[словарь не найден: {wordlist}]", []

    mode = JOHN_TO_HASHCAT.get(hash_format)
    if mode is None:
        return f"[неизвестный формат для hashcat: {hash_format}]", []

    out_file = hash_file + ".cracked"
    pot_file = hash_file + ".pot"

    cmd = [
        "hashcat", "-m", str(mode), "-a", "0",
        "--potfile-path", pot_file,
        "-o", out_file, "--outfile-format", "2",
        hash_file, wordlist,
        "--force", "--quiet",
    ]
    out = _run(cmd, timeout=timeout)

    cracked = []
    if os.path.exists(out_file):
        with open(out_file) as f:
            for line in f:
                line = line.strip()
                if ":" in line:
                    user, pw = line.split(":", 1)
                    cracked.append((user, pw))
                elif line:
                    cracked.append(("<hash>", line))
    return out, cracked


def crack_text(text, output_dir, label="shadow", max_runtime=120):
    """
    Умный взлом: сначала быстрый словарь (msf_defaults), потом rockyou с лимитом.
    """
    hashes = extract_hashes_from_text(text)
    if not hashes:
        return {"count": 0, "cracked": [], "hashes": [], "log": "хеши не найдены"}

    hash_file = os.path.join(output_dir, f"hashes_{label}.txt")
    save_hash_file(hashes, hash_file)

    fmt = detect_hash_type(hashes[0])
    print(f"    формат: {fmt}, хешей: {len(hashes)}")

    all_cracked = {}
    log_parts = []

    # ПРОХОД 1: маленький словарь дефолтных паролей
    fast_wordlist = os.path.join(_ROOT, "wordlists", "msf_defaults.txt")
    if os.path.exists(fast_wordlist):
        print(f"    [1/2] быстрый словарь: {os.path.basename(fast_wordlist)}")
        log1, cracked1 = run_john(
            hash_file,
            wordlist=fast_wordlist,
            hash_format=fmt,
            max_runtime=30,
        )
        log_parts.append(log1)
        for u, p in cracked1:
            all_cracked[u] = p
        if all_cracked:
            print(f"    -> взломано быстрым словарём: {len(all_cracked)}")

    # ПРОХОД 2: rockyou (только если что-то осталось)
    if len(all_cracked) < len(hashes):
        print(f"    [2/2] rockyou.txt (лимит {max_runtime}s)")
        log2, cracked2 = run_john(
            hash_file,
            wordlist=WORDLIST_ROCKYOU,
            hash_format=fmt,
            max_runtime=max_runtime,
        )
        log_parts.append(log2)
        for u, p in cracked2:
            all_cracked[u] = p

    cracked = list(all_cracked.items())
    return {
        "count": len(hashes),
        "hashes": hashes,
        "hash_file": hash_file,
        "format": fmt,
        "cracked": cracked,
        "log": "\n".join(log_parts),
    }


if __name__ == "__main__":
    demo = "test:$1$abc$qwertyuiopasdfghjklzxcvbnm:1000:1000::/home/test:/bin/sh"
    result = crack_text(demo, "/tmp/aegis_test", label="demo")
    print("Хешей:", result["count"])
    print("Формат:", result["format"])
    print("Взломано:", result["cracked"])
