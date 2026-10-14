# docker/apache-2449.Dockerfile
# Apache HTTP Server 2.4.49 — CVE-2021-41773 (traversal + RCE).
# Специально конфигурируем: Require all granted + mod_cgi + ScriptAlias.

FROM httpd:2.4.49

# 1. Показать оригинальный конфиг (для отладки в логах сборки)
RUN grep -nE "cgi_module|ScriptAlias|Require all" \
        /usr/local/apache2/conf/httpd.conf || true

# 2. Загружаем mod_cgi (regex ловит разные варианты строки)
RUN sed -ri 's|^#?\s*(LoadModule\s+cgi_module.*)$|\1|' \
        /usr/local/apache2/conf/httpd.conf

# 3. Открываем / — делает уязвимым к CVE-2021-41773
RUN sed -ri 's|Require\s+all\s+denied|Require all granted|g' \
        /usr/local/apache2/conf/httpd.conf

# 4. Активируем ScriptAlias для /cgi-bin/
RUN sed -ri 's|^#\s*(ScriptAlias\s+/cgi-bin/)|\1|' \
        /usr/local/apache2/conf/httpd.conf

# 5. Явно добавляем блок <Directory /cgi-bin> с ExecCGI
RUN printf '\n<Directory "/usr/local/apache2/cgi-bin">\n\
    AllowOverride None\n\
    Options +ExecCGI\n\
    Require all granted\n\
</Directory>\n' >> /usr/local/apache2/conf/httpd.conf

# 6. Тестовый CGI-скрипт (запускает /bin/sh)
RUN mkdir -p /usr/local/apache2/cgi-bin \
 && printf '#!/bin/sh\necho "Content-Type: text/plain"\necho\nid\n' \
        > /usr/local/apache2/cgi-bin/test.cgi \
 && chmod 755 /usr/local/apache2/cgi-bin/test.cgi

# 7. Проверка на этапе сборки — падаем, если mod_cgi не загрузился
RUN httpd -M | grep -q cgi_module \
    || (echo "FAIL: mod_cgi not loaded" && exit 1)

EXPOSE 80
