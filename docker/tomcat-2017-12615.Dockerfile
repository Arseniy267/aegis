# docker/tomcat-2017-12615.Dockerfile
# Apache Tomcat 8.5.19 с readonly=false для DefaultServlet — CVE-2017-12615.
#
# readonly=false должен быть <init-param> ВНУТРИ <servlet>DefaultServlet</servlet>.
# Context-level <Parameter> НЕ работает (Tomcat его игнорирует для DefaultServlet).
#
# Патчим через awk — надёжнее sed-вставки.

FROM tomcat:8.5.19

# Убираем ненужные приложения (быстрее старт)
RUN rm -rf /usr/local/tomcat/webapps/docs \
           /usr/local/tomcat/webapps/examples \
           /usr/local/tomcat/webapps/host-manager

# Вставляем <init-param>readonly=false</init-param> сразу после
# <servlet-class>...DefaultServlet</servlet-class>
RUN awk '\
/<servlet-class>org.apache.catalina.servlets.DefaultServlet<\/servlet-class>/ {\
    print;\
    print "        <init-param>";\
    print "            <param-name>readonly</param-name>";\
    print "            <param-value>false</param-value>";\
    print "        </init-param>";\
    next\
}\
{ print }\
' /usr/local/tomcat/conf/web.xml > /tmp/web_new.xml \
 && mv /tmp/web_new.xml /usr/local/tomcat/conf/web.xml \
 && grep -q "<param-name>readonly</param-name>" /usr/local/tomcat/conf/web.xml \
 || (echo "FAIL: readonly not inserted" && cat /usr/local/tomcat/conf/web.xml | head -50 && exit 1)

# Показать результат в логе сборки
RUN grep -B2 -A4 "readonly" /usr/local/tomcat/conf/web.xml

EXPOSE 8080
