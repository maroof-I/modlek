FROM php:apache

RUN docker-php-ext-install mysqli pdo pdo_mysql

RUN a2enmod rewrite

COPY ./php-cms-project /var/www/html/
RUN chown -R www-data:www-data /var/www/html

RUN ln -s /var/www/html/admin /admin

EXPOSE 80
