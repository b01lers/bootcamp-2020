FROM ubuntu:20.04

RUN apt-get update
RUN apt-get install python3 -y
RUN apt-get install python3-pip -y

ENV USER crypto_training
WORKDIR /home/$USER
RUN useradd $USER

RUN pip3 install flask

COPY ./deploy/deploy ./

CMD ["python3", "./server.py"]
