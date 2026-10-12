```python
import socket
import ssl
```

Теперь опиши функцию для проверки сервиса RTSP:

```python
def check_rtsp(ip, port):
    try:
        # Создаём сокет
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Соединяемся
        s.connect((ip, port))
        # Выполняем проверку сертификата (SSL)
        ssl_sock = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_TLSv1)
        # Проверяем сертификат
        ssl_sock.getpeercert()
        # Закрываем соединение
        s.close()
        return "service_up"
    except Exception as e:
        return f"service_down: {e}"
```

Теперь проверяем RTSP на 127.0.0.1 и выводим результат:

```python
if __name__ == "__main__":
    # Запускаем проверку сервиса
    result = check_rtsp('127.0.0.1', 5000)
    # Выводим результат
    print(result)
```

Запускаем скрипт и получаем ответ:

```bash
python3 aegis_rtsp.py
```

Если сервис работает, вы должны увидеть `service_up`. Если сервис отвечает ошибкой или не работает, вы увидите `service_down`.