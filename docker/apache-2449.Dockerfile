# docker/apache-2449.Dockerfile
FROM httpd:2.4.49

# 1. Debug: показать оригинал (в логах сборки)
RUN grep -nE "cgi_module|ScriptAlias|Require all" \
        /usr/local/apache2/conf/httpd.conf || true

# 2. Разкомментировать LoadModule cgi_module (учитываем пробелы и tabs перед #)
RUN sed -ri 's|^([[:space:]]*)#([[:space:]]*)(LoadModule[[:space:]]+cgi_module.*)$|\1\3|' \
        /usr/local/apache2/conf/httpd.conf

# 3. Разкомментировать cgid_module тоже (мод для многопоточного CGI)
RUN sed -ri 's|^([[:space:]]*)#([[:space:]]*)(LoadModule[[:space:]]+cgid_module.*)$|\1\3|' \
        /usr/local/apache2/conf/httpd.conf

# 4. Заменить Require all denied → granted (для CVE-2021-41773)
RUN sed -ri 's|Require[[:space:]]+all[[:space:]]+denied|Require all granted|g' \
        /usr/local/apache2/conf/httpd.conf

# 5. Разкомментировать ScriptAlias (учитывая пробелы)
RUN sed -ri 's|^([[:space:]]*)#([[:space:]]*)(ScriptAlias[[:space:]]+/cgi-bin/.*)$|\1\3|' \
        /usr/local/apache2/conf/httpd.conf

# 6. Явный <Directory> для cgi-bin (Options +ExecCGI + Require all granted)
RUN printf '\n<Directory "/usr/local/apache2/cgi-bin">\n\
    AllowOverride None\n\
    Options +ExecCGI\n\
    Require all granted\n\
</Directory>\n' >> /usr/local/apache2/conf/httpd.conf

# 7. Тестовый CGI-скрипт
RUN mkdir -p /usr/local/apache2/cgi-bin \
 && printf '#!/bin/sh\necho "Content-Type: text/plain"\necho\nid\n' \
        > /usr/local/apache2/cgi-bin/test.cgi \
 && chmod 755 /usr/local/apache2/cgi-bin/test.cgi

# 8. Проверка: mod_cgi действительно загружен? Если нет — упасть с логом.
RUN httpd -t 2>&1 | head -20 ; \
    if ! httpd -M 2>/dev/null | grep -q cgi_module; then \
        echo "=== httpd.conf cgi-related lines ==="; \
        grep -nE "cgi_module|ScriptAlias" /usr/local/apache2/conf/httpd.conf; \
        echo "FAIL: mod_cgi not loaded"; \
        exit 1; \
    fi
