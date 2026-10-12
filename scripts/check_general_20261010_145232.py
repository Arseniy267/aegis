import socket

def check_rtsp(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((host, port))
            s.sendall(b"DESCRIBE rtsp://127.0.0.1 RTSP/1.0\r\n\r\n")
            data = s.recv(1024)
            if b"RTSP/1.0 200 OK" in data:
                print(f"RTSP service is running on {host}:{port}")
            else:
                print(f"RTSP service is not responding correctly on {host}:{port}")
    except Exception as e:
        print(f"Error connecting to {host}:{port}: {e}")

check_rtsp("127.0.0.1", 5000)