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
import select

def check_telnet(ip, port=23):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((ip, port))
        s.send(b'Trying to connect to ' + ip.encode() + b'\r\n')
        s.send(b'Please enter your username: ')
        s.send(b'Please enter your password: ')
        s.send(b'Login incorrect\r\n')
        s.close()
        return True
    except socket.error:
        return False

# Теперь добавьте логику, которая будет проверять, что сервер ответил на
# запрос 'Trying to connect to ' + ip.encode() + '\r\n'
# и что сервер ответил 'Login incorrect\r\n'

Примечание: Этот код предназначен для использования в тестовой среде.

### Решение:

import socket
import select

def check_telnet(ip, port=23):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((ip, port))
        s.send(b'Trying to connect to ' + ip.encode() + b'\r\n')
        s.send(b'Please enter your username: ')
        s.send(b'Please enter your password: ')
        s.send(b'Login incorrect\r\n')
        s.close()
        return True
    except socket.error:
        return False

# Теперь добавьте логику, которая будет проверять, что сервер ответил на
# запрос 'Trying to connect to ' + ip.encode() + '\r\n'
# и что сервер ответил 'Login incorrect\r\n'

def check_telnet_response(ip):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((ip, 23))
        s.send(b'Trying to connect to ' + ip.encode() + b'\r\n')
        s.send(b'Please enter your username: ')
        s.send(b'Please enter your password: ')
        s.send(b'Login incorrect\r\n')
        s.close()
        
        # Теперь добавляем логику для чтения ответа сервера
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((ip, 23))
        s.send(b'Trying to connect to ' + ip.encode() + b'\r\n')
        s.send(b'Please enter your username: ')
        s.send(b'Please enter your password: ')
        s.send(b'Login incorrect\r\n')
        
        # Ожидаем ответ сервера
        ready = select.select([s], [], [], 1)
        if ready[0]:
            data = s.recv(1024)
            if b'Trying to connect to ' + ip.encode() + b'\r\n' in data and b'Login incorrect\r\n' in data:
                s.close()
                return True
            else:
                s.close()
                return False
        else:
            s.close()
            return False
    except socket.error:
        return False

# Теперь вызываем функцию check_telnet_response
# и она должна вернуть True, если сервер ответил на запрос и 'Login incorrect\r\n'

Примечание: Этот код предназначен для использования в тестовой среде.