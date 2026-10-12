import socket

def check_rtsp_vulnerability(target_ip, target_port):
    try:
        # Создаем TCP/IP сокет
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Устанавливаем соединение с целевой машиной
            s.connect((target_ip, target_port))
            # Отправляем команду RTSP для проверки уязвимости CVE-2021-2831
            s.sendall(b"OPTIONS * RTSP/1.0\r\n\r\n")
            # Получаем ответ от сервера
            data = s.recv(1024)
            # Проверяем наличие уведомления о уязвимости
            if b"CVE-2021-2831" in data:
                print("Уязвимость CVE-2021-2831 обнаружена")
            else:
                print("Уязвимость CVE-2021-2831 не обнаружена")
    except Exception as e:
        print(f"Ошибка при проверке уязвимости: {e}")

# Проверяем целевую машину
check_rtsp_vulnerability("127.0.0.1", 5000)