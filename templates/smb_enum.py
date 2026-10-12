# SMB enumeration template
import subprocess
import sys

def enum_smb(host):
    print(f"[+] SMB enum: {host}")
    try:
        r = subprocess.run(["smbclient", "-L", host, "-N"],
                           capture_output=True, text=True, timeout=30)
        print(r.stdout[:1500])
        if r.stderr:
            print("[stderr]", r.stderr[:300])
    except Exception as e:
        print(f"[-] {e}")

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    enum_smb(host)