import socket
import ssl
import http.client
import urllib.request
import subprocess
import os
import sys

# Определить хост и порт
HOST = '192.168.64.7'
PORT = 80

# Функция проверки открытого порта
def check_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            print(f"Порт {port} открыт")
            return True
        else:
            print(f"Порт {port} закрыт")
            return False
    except socket.error as err:
        print(f"Ошибка соединения: {err}")
        sys.exit()
    finally:
        sock.close()

# Функция получения баннера
def get_banner(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        sock.send(b'HEAD / HTTP/1.1\r\nHost: ' + host.encode() + b'\r\n\r\n')
        return sock.recv(1024)
    except socket.error as err:
        print(f"Ошибка получения баннера: {err}")
        sys.exit()
    finally:
        sock.close()

# Проверка открытия порта
if check_port(HOST, PORT):
    # Получение и вывод баннера
    banner = get_banner(HOST, PORT)
    print(f"Баннер сервиса: {banner}")
else:
    print("Не удалось получить баннер, порт закрыт.")
```

Этот скрипт проверяет, открыт ли порт 80 на 192.168.64.7, и, если открыт, получает баннер сервиса.

Чтобы запустить скрипт, выполни:
```bash
python3 script.py
```

В случае успешного выполнения вы увидите сообщение о том, что порт открыт, и баннер сервиса.

В случае ошибки или если порт закрыт, вы увидите соответствующее сообщение.