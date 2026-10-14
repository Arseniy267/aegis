# docker/tomcat-2017-12615.Dockerfile
# Apache Tomcat 8.5.19 с readonly=false для DefaultServlet — CVE-2017-12615.
#
# ВАЖНО: readonly=false задаётся НЕ в conf/web.xml (сломает парсер),
# а как <Context> в conf/server.xml внутри <Host>.

FROM tomcat:8.5.19

# Убираем дефолтные приложения (не нужны для теста)
RUN rm -rf /usr/local/tomcat/webapps/docs \
           /usr/local/tomcat/webapps/examples \
           /usr/local/tomcat/webapps/host-manager

# Добавляем <Context> в server.xml с readonly=false
# Используем Python для корректной вставки XML (sed опасен)
RUN python3 - <<'PYEOF'
import re

path = "/usr/local/tomcat/conf/server.xml"
with open(path, encoding="utf-8") as f:
    content = f.read()

context_block = """
        <Context path="" docBase="ROOT" reloadable="true">
            <Parameter name="readonly" value="false" override="false"/>
        </Context>
"""

# Вставляем Context прямо перед закрывающим </Host>
if "</Host>" not in content:
    raise SystemExit("FAIL: </Host> not found in server.xml")

content = content.replace("</Host>", context_block + "\n      </Host>", 1)

with open(path, "w", encoding="utf-8") as f:
    f.write(content)

print("OK: Context block inserted into server.xml")
PYEOF

# Показываем результат для отладки
RUN grep -B2 -A3 'Context path=""' /usr/local/tomcat/conf/server.xml

EXPOSE 8080
