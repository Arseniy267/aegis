# FTP check template
import socket
import sys

def check_ftp(host, port=21):
    try:
        s = socket.socket()
        s.settimeout(5)
        s.connect((host, port))
        banner = s.recv(1024)
        print(f"[+] FTP banner: {banner.decode(errors='ignore')[:200]}")
        s.send(b"USER anonymous\r\n")
        resp = s.recv(1024)
        print(f"[+] USER response: {resp.decode(errors='ignore')[:100]}")
        s.close()
        return True
    except Exception as e:
        print(f"[-] FTP check failed: {e}")
        return False

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 21
    check_ftp(host, port)