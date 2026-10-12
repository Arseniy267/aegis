# HTTP check template
import sys
import urllib.request

def check_http(host, port=80, path="/"):
    try:
        url = f"http://{host}:{port}{path}"
        req = urllib.request.Request(url, headers={"User-Agent": "AEGIS/1.5"})
        resp = urllib.request.urlopen(req, timeout=10)
        print(f"[+] HTTP status: {resp.status}")
        print(f"[+] Server: {resp.headers.get('Server', 'N/A')}")
        print(f"[+] X-Powered-By: {resp.headers.get('X-Powered-By', 'N/A')}")
        body = resp.read(500).decode(errors="ignore")
        print(f"[+] Preview: {body[:200]}")
        return True
    except Exception as e:
        print(f"[-] HTTP check failed: {e}")
        return False

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    check_http(host, port)