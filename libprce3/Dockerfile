FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -y && apt-get install -y apt-src build-essential devscripts dpkg-dev libfaketime

RUN \
    echo "deb http://us.archive.ubuntu.com/ubuntu/ focal main restricted" > /etc/apt/sources.list && \
    echo "deb-src http://us.archive.ubuntu.com/ubuntu/ focal main restricted" >> /etc/apt/sources.list && \
    apt-get update -y

# Add the source repositories to the sources.list file
RUN echo "deb-src http://archive.ubuntu.com/ubuntu/ focal main restricted" >> /etc/apt/sources.list

WORKDIR /deb
RUN apt source libpcre3 && apt build-dep libpcre3 -y

COPY src /src

RUN /src/patch.sh

RUN mkdir /build && touch /build/.keepdir

WORKDIR /src

RUN if [ -f ./build.sh ]; then ./build.sh; fi

RUN touch .keepdir

FROM ubuntu:22.04

RUN apt-get update && apt-get install -y curl nginx strace socat libfaketime netcat wget

COPY --from=builder /build/ /opt/
RUN dpkg -i /opt/libpcre3_8.39-16_amd64.deb

COPY ./src/run* /opt/
RUN rm /opt/.keepdir -f

COPY ./src/dist/nginx.conf /etc/nginx/nginx.conf
ADD ./src/html /var/www/html

RUN adduser --no-create-home --disabled-password --gecos "" user

RUN mkdir -p /var/lib/nginx/ && chown -R user:user /var/lib/nginx/ && \
    mkdir -p /var/log/nginx/ && chown -R user:user /var/log/nginx/ && \
    chown -R user:user /run/ 

USER user

WORKDIR /opt

CMD /opt/run_challenge.sh
