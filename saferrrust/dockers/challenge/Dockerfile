# =============== Building Challenge In Docker  =============== 
# I don't want to rebuild it everytime, if offsets change the exploit will not work
# There is a script: src/build.sh which should be everything and put it in the right place

# =============== Production Challenge Environment  ===============
# This part of the docker file defines the runtime environment for your challenge
# Please follow the steps below:

# CHAL AUTHOR: Choose your base distro to run the challenge on.
# Some examples: debian:bullseye, ubuntu:22.04, alpine:latest, fedora:latest
# Or any other base docker image
FROM ubuntu:22.04

# CHAL AUTHOR: If you have any runtime dependencies, install them here
# example: installing curl from apt
RUN apt-get update && apt-get install -y curl
RUN apt-get install -y expect htop strace vim screen psmisc

# Copy all prebuilt files from ./bin/
RUN mkdir /opt/writablefolder
COPY ./bin/run_challenge.sh /opt/
COPY ./bin/saferrrust /opt/

# Add a user to run the challenge (uid 1000)
RUN adduser --no-create-home --disabled-password --gecos "" user
RUN chown user:user /opt/writablefolder/
#RUN chmod 777 /opt/
USER user

# Set the working directory for the challenge
WORKDIR /opt

# CHAL AUTHOR: Command to run your challenge
#CMD /bin/bash
CMD /opt/run_challenge.sh

