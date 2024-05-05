# syntax=docker/dockerfile:1

FROM debian:bullseye-slim

RUN apt-get clean \
    && apt-get -y update

RUN apt-get -y install nginx \
    && apt-get -y install python3-dev \
    && apt-get -y install python3-pip \
    && apt-get -y install build-essential

RUN pip3 install -U pip

COPY requirements.txt /root/requirements.txt
RUN pip3 install -r /root/requirements.txt

COPY amib_server /root/amib_server
COPY uwsgi.ini /root/
COPY start.sh /root/
WORKDIR /root

CMD ["python3", "-m" , "flask",  "--app=amib_server", "run", "--host=0.0.0.0"]

#COPY nginx.conf /etc/nginx
#RUN chown -R www-data:www-data .
#RUN chmod +x ./start.sh
#CMD ["./start.sh"]
