# MySQL check template
import socket
import sys

def check_mysql(host, port=3306):
    try:
        s = socket.socket()
        s.settimeout(5)
        s.connect((host, port))
        banner = s.recv(1024)
        print(f"[+] MySQL banner: {banner.decode(errors='ignore')[:200]}")
        s.close()
        return True
    except Exception as e:
        print(f"[-] MySQL check failed: {e}")
        return False

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 3306
    check_mysql(host, port)