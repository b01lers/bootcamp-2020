FROM ubuntu:20.04

RUN apt-get update
RUN apt-get install -y build-essential
RUN apt-get install -y python3
RUN apt-get install -y python3-pip

RUN mkdir -p /var/www/enflaskcom/
WORKDIR /var/www/enflaskcom/

COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY flag.txt server.py ./

CMD ["python3", "./server.py"]
