# docker/vsftpd-234.Dockerfile
# vsftpd 2.3.4 с backdoor (CVE-2011-2523) для локального теста AEGIS.
# Скачиваем оригинальный tarball с backdoor (до того, как его убрали).

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential wget ca-certificates libssl-dev libpam0g-dev \
    && rm -rf /var/lib/apt/lists/*

# Оригинальный vsftpd 2.3.4 С BACKDOOR (из archive, до удаления)
# Если ссылка недоступна — используем заранее скачанный файл из /tmp
WORKDIR /tmp

# Способ 1: скачать оригинал (архивы Apache часто убирают)
RUN wget -q https://src.fedoraproject.org/repo/pkgs/vsftpd/vsftpd-2.3.4.tar.gz/sha512/... \
        -O vsftpd-2.3.4.tar.gz || echo "DOWNLOAD_FAILED"

# Если скачать не удалось — используем минимальный vsftpd из apt
# (он БЕЗ backdoor — тогда PoC не сработает, но механизм проверим)
RUN if [ ! -f vsftpd-2.3.4.tar.gz ]; then \
        apt-get update && apt-get install -y vsftpd && \
        echo "USING APT VSFTPD (no backdoor)" > /tmp/note.txt; \
    fi

RUN if [ -f vsftpd-2.3.4.tar.gz ]; then \
        tar xzf vsftpd-2.3.4.tar.gz && \
        cd vsftpd-2.3.4 && \
        sed -i 's|^#define VSF_BUILD_SSL|#define VSF_BUILD_SSL|' builddefs.h && \
        make && \
        cp vsftpd /usr/local/sbin/vsftpd && \
        cp vsftpd.conf /etc/vsftpd.conf && \
        mkdir -p /var/ftp && \
        useradd -d /var/ftp ftp || true; \
    fi

RUN mkdir -p /var/run/vsftpd/empty

EXPOSE 21 6200

CMD ["sh", "-c", "if [ -x /usr/local/sbin/vsftpd ]; then /usr/local/sbin/vsftpd /etc/vsftpd.conf; else vsftpd; fi"]
