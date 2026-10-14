# docker/sandbox.Dockerfile
FROM python:3.12-slim-bookworm

# Метаданные
LABEL org.opencontainers.image.title="aegis-sandbox"
LABEL org.opencontainers.image.description="AEGIS PoC execution sandbox"

# Минимальные системные утилиты (для отладки PoC)
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Python-пакеты для пентест-скриптов
RUN pip install --no-cache-dir \
        requests==2.32.3 \
        httpx==0.27.2 \
        impacket==0.12.0 \
        paramiko==3.4.1 \
        pymysql==1.1.1 \
        beautifulsoup4==4.12.3 \
        lxml==5.3.0 \
        pwntools==4.13.1

# Непривилегированный пользователь
RUN useradd -m -u 1000 -s /bin/bash sandbox
USER sandbox
WORKDIR /home/sandbox

# Ничего больше — скрипт монтируется в /poc.py
ENTRYPOINT ["python", "/poc.py"]
