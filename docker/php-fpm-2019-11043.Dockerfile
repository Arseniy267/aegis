# docker/php-fpm-2019-11043.Dockerfile
# PHP-FPM 7.1.32 + nginx — уязвимо к CVE-2019-11043 (underflow RCE).
# nginx с fastcgi_split_path_info, где regex имеет баг.

FROM php:7.1.32-fpm-alpine

# Устанавливаем nginx
RUN apk add --no-cache nginx

# Конфиг nginx с УЯЗВИМЫМ fastcgi_split_path_info
# (баг: regex не ограничивает path_info правильно)
RUN mkdir -p /var/www/html /run/nginx /var/log/nginx && \
    printf '%s\n' \
'worker_processes 1;' \
'events { worker_connections 128; }' \
'http {' \
'    include /etc/nginx/mime.types;' \
'    server {' \
'        listen 80 default_server;' \
'        root /var/www/html;' \
'        index index.php;' \
'' \
'        location ~ [^/]\.php(/|$) {' \
'            fastcgi_split_path_info ^(.+?\.php)(/.*)$;' \
'            fastcgi_param PATH_INFO $fastcgi_path_info;' \
'            fastcgi_pass 127.0.0.1:9000;' \
'            fastcgi_index index.php;' \
'            include fastcgi_params;' \
'        }' \
'    }' \
'}' \
> /etc/nginx/nginx.conf

# Тестовый PHP-файл
RUN printf '<?php echo "php-fpm-ok"; phpinfo();' > /var/www/html/index.php

EXPOSE 80

# nginx в фоне + php-fpm в foreground
CMD ["sh", "-c", "nginx && php-fpm"]
