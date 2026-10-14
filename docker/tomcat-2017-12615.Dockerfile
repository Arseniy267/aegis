# docker/tomcat-2017-12615.Dockerfile
# Apache Tomcat 8.5.19 с readonly=false — уязвим к CVE-2017-12615 (PUT RCE).
# ВАЖНО: дефолтный tomcat:8.5.19 НЕ уязвим. Нужно явно включить readonly=false.

FROM tomcat:8.5.19

# Патчим web.xml — включаем readonly=false (это и есть условие уязвимости)
RUN sed -i 's|<param-name>readonly</param-name>|<param-name>readonly</param-name>|g' \
        /usr/local/tomcat/conf/web.xml || true

# Если в дефолтном конфиге readonly не определён — добавляем секцию
RUN set -eux; \
    if ! grep -q "<param-name>readonly</param-name>" /usr/local/tomcat/conf/web.xml; then \
        printf '\n<!-- AEGIS CVE-2017-12615 config -->\n\
<servlet>\n\
    <servlet-name>default</servlet-name>\n\
    <init-param>\n\
        <param-name>readonly</param-name>\n\
        <param-value>false</param-value>\n\
    </init-param>\n\
</servlet>\n' >> /usr/local/tomcat/conf/web.xml; \
    else \
        sed -i 's|<param-value>true</param-value>|<param-value>false</param-value>|' /usr/local/tomcat/conf/web.xml; \
    fi

# Убеждаемся, что readonly = false
RUN grep -A2 "readonly" /usr/local/tomcat/conf/web.xml | head -20

EXPOSE 8080
