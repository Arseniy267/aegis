# docker/drupal-2018-7600.Dockerfile
# Drupal 8.5.0 — уязвим к CVE-2018-7600 (Drupalgeddon2).
# Образ самодостаточен: SQLite-БД, автоматическая установка при первом старте.
# ВАЖНО: первый запуск — 2-3 минуты (установка Drupal + наполнение).

FROM drupal:8.5.0

# Даём права на sites/default/files — нужно для Form API
RUN chmod -R 777 /var/www/html/sites/default \
    || mkdir -p /var/www/html/sites/default/files \
    && chmod -R 777 /var/www/html/sites/default

EXPOSE 80
