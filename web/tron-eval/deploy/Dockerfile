FROM php:7.2-apache

WORKDIR /var/www/html/

RUN mkdir packets
COPY packets packets/
COPY index.php sjcl.js style.css tron.css ./
RUN chmod 664 index.php sjcl.js style.css tron.css packets/send.php packets/sent/flag.packet.php && chmod 757 packets/sent

CMD ["apache2-foreground"]
