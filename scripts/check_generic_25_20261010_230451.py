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

# LLM дополнение:
import socket
import smtplib

def check_smtp(host, port=25):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            if result == 0:
                print(f"SMTP server is running on {host}:{port}")
                try:
                    smtp_server = smtplib.SMTP(host, port)
                    smtp_server.helo()
                    print("SMTP server is ready for sending emails.")
                except smtplib.SMTPException as e:
                    print(f"Error: {e}")
            else:
                print(f"SMTP server is not running on {host}:{port}")
    except socket.error as e:
        print(f"Socket error: {e}")

# Example usage:
check_smtp('localhost')

Пример использования:

check_smtp('localhost')

Пример вывода:

SMTP server is running on localhost:25
SMTP server is ready for sending emails.

Если SMTP-сервер не запущен, вы должны увидеть сообщение:

SMTP server is not running on localhost:25

Если возникла ошибка сокета, вы должны увидеть сообщение:

Socket error: [Errno 111] Connection refused