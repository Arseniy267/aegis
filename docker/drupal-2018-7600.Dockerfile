# docker/drupal-2018-7600.Dockerfile
# Drupal 8.5.0 — уязвим к CVE-2018-7600 (Drupalgeddon2).
# RCE через Form API: параметр element_parents в AJAX-запросе.

FROM drupal:8.5.0

# Vulhub-стиль: разрешаем анонимную регистрацию + правим конфиг
RUN set -eux; \
    chmod -R 777 /var/www/html/sites/default 2>/dev/null || true

EXPOSE 80
