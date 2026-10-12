# Generic port check template
import socket
import sys

def check_port(host, port):
    try:
        s = socket.socket()
        s.settimeout(5)
        result = s.connect_ex((host, int(port)))
        if result == 0:
            print(f"[+] Port {port} is open")
            try:
                s.settimeout(3)
                banner = s.recv(1024)
                if banner:
                    print(f"[+] Banner: {banner.decode(errors='ignore')[:200]}")
            except socket.timeout:
                pass
            s.close()
            return True
        else:
            print(f"[-] Port {port} is closed")
            s.close()
            return False
    except Exception as e:
        print(f"[-] Check failed: {e}")
        return False

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = sys.argv[2] if len(sys.argv) > 2 else "80"
    check_port(host, port)