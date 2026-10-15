# docker/apache-2449.Dockerfile
# Apache 2.4.49 — уязвим к CVE-2021-41773 (traversal + RCE).
# Минимальный конфиг. Гарантированно: <Directory /> Require all granted.

FROM httpd:2.4.49

RUN printf '%s\n' \
'ServerName localhost' \
'Listen 80' \
'' \
'LoadModule mpm_event_module    modules/mod_mpm_event.so' \
'LoadModule authn_core_module   modules/mod_authn_core.so' \
'LoadModule authz_core_module   modules/mod_authz_core.so' \
'LoadModule authz_host_module   modules/mod_authz_host.so' \
'LoadModule unixd_module        modules/mod_unixd.so' \
'LoadModule dir_module          modules/mod_dir.so' \
'LoadModule mime_module         modules/mod_mime.so' \
'LoadModule log_config_module   modules/mod_log_config.so' \
'LoadModule alias_module        modules/mod_alias.so' \
'LoadModule cgi_module          modules/mod_cgi.so' \
'' \
'User www-data' \
'Group www-data' \
'' \
'DocumentRoot "/usr/local/apache2/htdocs"' \
'' \
'# --- КЛЮЧЕВОЕ: без этого traversal даёт 403 ---' \
'<Directory />' \
'    AllowOverride None' \
'    Require all granted' \
'    Options +ExecCGI' \
'    AddHandler cgi-script .cgi .sh' \
'</Directory>' \
'' \
'<Directory "/usr/local/apache2/htdocs">' \
'    AllowOverride None' \
'    Require all granted' \
'</Directory>' \
'' \
'Alias /icons/ "/usr/local/apache2/icons/"' \
'<Directory "/usr/local/apache2/icons">' \
'    AllowOverride None' \
'    Options Indexes MultiViews' \
'    Require all granted' \
'</Directory>' \
'' \
'ScriptAlias /cgi-bin/ "/usr/local/apache2/cgi-bin/"' \
'<Directory "/usr/local/apache2/cgi-bin">' \
'    AllowOverride None' \
'    Options +ExecCGI' \
'    Require all granted' \
'</Directory>' \
'' \
'ErrorLog  /proc/self/fd/2' \
'TransferLog /proc/self/fd/1' \
'' \
'TypesConfig conf/mime.types' \
> /usr/local/apache2/conf/httpd.conf

# Тестовые CGI-скрипты
RUN mkdir -p /usr/local/apache2/cgi-bin \
 && printf '#!/bin/sh\necho "Content-Type: text/plain"\necho\nid\n' \
        > /usr/local/apache2/cgi-bin/test.cgi \
 && chmod 755 /usr/local/apache2/cgi-bin/test.cgi \
 && printf '#!/bin/sh\necho "Content-Type: text/plain"\necho\nid\n' \
        > /usr/local/apache2/htdocs/evil.sh \
 && chmod 755 /usr/local/apache2/htdocs/evil.sh

# Проверка на этапе сборки
RUN httpd -t 2>&1 | head -20 && \
    httpd -M 2>/dev/null | grep -q cgi_module || \
    (echo "FAIL: cgi_module missing"; httpd -M 2>/dev/null; exit 1) && \
    echo "OK: build passed, cgi_module loaded"

EXPOSE 80
