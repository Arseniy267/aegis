# docker/tomcat-2017-12615.Dockerfile
# Apache Tomcat 8.5.19 с readonly=false для ROOT-приложения — CVE-2017-12615.
#
# Способ: per-app context в conf/Catalina/localhost/ROOT.xml
# (не трогаем server.xml, не трогаем web.xml — оба парсятся строго)

FROM tomcat:8.5.19

# Убираем ненужные приложения (быстрее старт)
RUN rm -rf /usr/local/tomcat/webapps/docs \
           /usr/local/tomcat/webapps/examples

# Создаём директорию для per-app конфигов + ROOT.xml с readonly=false
RUN mkdir -p /usr/local/tomcat/conf/Catalina/localhost \
 && printf '%s\n' \
'<?xml version="1.0" encoding="UTF-8"?>' \
'<Context path="" docBase="ROOT" reloadable="true">' \
'    <Parameter name="readonly" value="false" override="false"/>' \
'</Context>' \
> /usr/local/tomcat/conf/Catalina/localhost/ROOT.xml

# Проверка на этапе сборки
RUN cat /usr/local/tomcat/conf/Catalina/localhost/ROOT.xml

EXPOSE 8080
