# docker/apache-2449.Dockerfile
# Apache HTTP Server 2.4.49, уязвимый к CVE-2021-41773 (path traversal + RCE).
# Специально конфигурируем под уязвимость — для локального теста AEGIS.

FROM httpd:2.4.49

# 1. Включить mod_cgi
RUN sed -i 's|^#LoadModule cgi_module|LoadModule cgi_module|' \
        /usr/local/apache2/conf/httpd.conf

# 2. Заменить "Require all denied" на "Require all granted"
#    ЭТО ключевой фикс — делает Apache уязвимым (типовая ошибка конфига).
RUN sed -i 's|Require all denied|Require all granted|g' \
        /usr/local/apache2/conf/httpd.conf

# 3. ScriptAlias для /cgi-bin/
RUN sed -i 's|^#ScriptAlias /cgi-bin/|ScriptAlias /cgi-bin/|' \
        /usr/local/apache2/conf/httpd.conf

# 4. Разрешить CGI в /cgi-bin/
RUN printf '\n<Directory "/usr/local/apache2/cgi-bin">\n\
    AllowOverride None\n\
    Options +ExecCGI\n\
    Require all granted\n\
</Directory>\n' >> /usr/local/apache2/conf/httpd.conf

# 5. Простой CGI-скрипт (для отладки mod_cgi)
RUN mkdir -p /usr/local/apache2/cgi-bin \
 && printf '#!/bin/sh\necho "Content-Type: text/plain"\necho\nid\n' \
        > /usr/local/apache2/cgi-bin/test.cgi \
 && chmod 755 /usr/local/apache2/cgi-bin/test.cgi

EXPOSE 80
