## This is an approximation of the actual production environment, there may be minor differences
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y curl git
RUN adduser --disabled-password --gecos "" user
USER user

RUN curl -sSL https://dot.net/v1/dotnet-install.sh | bash /dev/stdin --version 6.0.412
ENV DOTNET_ROOT="/home/user/.dotnet"
ENV PATH="${PATH}:/home/user/.dotnet:/home/user/.dotnet/tools"
ENV DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=true

USER root
COPY server/* /opt/

USER user
WORKDIR /opt
CMD dotnet /opt/npcua.nautilus.dll
