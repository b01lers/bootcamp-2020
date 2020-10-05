FROM mysql:5.7

RUN apt-get update \
    && apt-get install -y python3 \
    && apt-get install -y python3-mysqldb \
    && apt-get install -y python3-pip

RUN pip3 install flask

COPY entrypoint.sh /
COPY static/ static/
COPY db_create.py .
COPY server.py .
COPY templates templates/
COPY data data/

CMD ["mysqld"]
