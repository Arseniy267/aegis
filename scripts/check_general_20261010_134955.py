import socket

def check_general(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            print(f"Port {port} is open")
        else:
            print(f"Port {port} is closed")
        sock.close()
    except socket.error as e:
        print(f"Socket error: {e}")

if __name__ == "__main__":
    target_ip = "127.0.0.1"
    port = 5000
    check_general(target_ip, port)