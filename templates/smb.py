# SMB check template
import socket
import sys

def check_smb(host, port=445):
    try:
        s = socket.socket()
        s.settimeout(5)
        s.connect((host, port))
        # SMB Negotiate Protocol Request
        payload = bytes([
            0x00, 0x00, 0x00, 0x85, 0xFF, 0x53, 0x4D, 0x42, 0x72, 0x00,
            0x00, 0x00, 0x00, 0x18, 0x53, 0xC8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00
        ])
        s.send(payload)
        resp = s.recv(1024)
        if len(resp) > 0:
            print(f"[+] SMB response received ({len(resp)} bytes)")
            s.close()
            return True
        s.close()
        return False
    except Exception as e:
        print(f"[-] SMB check failed: {e}")
        return False

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 445
    check_smb(host, port)