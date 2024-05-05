# =============== Production Challenge Environment  ===============
# This part of the docker file defines the runtime environment for your challenge
# Please follow the steps below:

# CHAL AUTHOR: Choose your base distro to run the challenge on.
# Some examples: debian:bullseye, ubuntu:22.04, alpine:latest, fedora:latest
# Or any other base docker image
FROM ubuntu:22.04

# CHAL AUTHOR: If you have any runtime dependencies, install them here
# example: installing curl from apt

ENV DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC

RUN apt-get update
RUN apt-get install -y curl
RUN apt-get install -y python3 python3-pip
RUN apt-get install -y expect htop strace vim screen psmisc
RUN python3 -m pip install --upgrade pip && python3 -m pip install --upgrade pwntools
RUN pip install python-chess

# Copy all prebuilt files from ./bin/
COPY ./bin/run_challenge.sh /opt/
COPY ./bin/play_min.py /opt/
COPY ./bin/thinkingharder /opt/
COPY ./bin/xy_python.bin /opt/
RUN bash -c 'cd /opt && XZ_OPT="-9e" tar -cJf hikarrro.tar.xz xy_python.bin thinkingharder play_min.py run_challenge.sh'


# Add a user to run the challenge (uid 1000)
RUN adduser --no-create-home --disabled-password --gecos "" user
USER user

# Set the working directory for the challenge
WORKDIR /opt

# CHAL AUTHOR: Command to run your challenge
CMD /opt/run_challenge.sh
#CMD /bin/bash

