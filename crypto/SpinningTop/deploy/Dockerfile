FROM ubuntu:20.04

# Change example to the name of your challenge.
ENV USER spinningtop

WORKDIR /home/$USER

RUN useradd $USER
RUN apt-get update
RUN apt-get install -y xinetd
RUN apt-get update
RUN apt-get install -y python3
RUN apt-get install -y python3-pip
RUN python3 -m pip install PyCryptodome

COPY ./deploy/wrapper.sh /home/$USER/
COPY ./deploy/$USER.xinetd /etc/xinetd.d/$USER
COPY ./src/$USER.py /home/$USER/

RUN chown -R root:$USER /home/$USER
RUN chmod -R 550 /home/$USER

RUN touch /var/log/xinetdlog

EXPOSE 1337

CMD service xinetd start && sleep 2 && tail -f /var/log/xinetdlog
