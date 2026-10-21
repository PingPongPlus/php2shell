FROM php:8.4.4-fpm-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx procps curl python3 \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/log/php-fpm /var/lib/php/sessions /run/php \
    && chown www-data:www-data /var/lib/php/sessions

COPY conf/php.ini /usr/local/etc/php/php.ini
COPY conf/php-mitigated.ini /usr/local/etc/php/php-mitigated.ini
COPY conf/www.conf /usr/local/etc/php-fpm.d/www.conf
COPY conf/php-fpm.conf /usr/local/etc/php-fpm.conf
COPY conf/nginx.conf /etc/nginx/nginx.conf
COPY webroot/ /var/www/html/
COPY scripts/ /opt/scripts/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80
CMD ["/entrypoint.sh"]
