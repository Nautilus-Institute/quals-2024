# Example deployment
# Production server's environment may differ slightly
FROM ubuntu:22.04

# flag1 will only be here if you connect to the correct endpoint for the first part of the challenge (see challenge description)
RUN echo "flug{flag1 will be in here and is fairly long so write a good payload if you want to read it all}" > /flag1.txt && chmod o+r /flag1.txt

RUN adduser --no-create-home --disabled-password --gecos "" gov

# flag2 will only be here if you connect to the correct endpoint for the second part of the challenge (see challenge description)
RUN mkdir /treasury/ && \
    echo "flug{flag2 will be here and will also probably be long so you better write a good exploit if you want that bailout money}" > /treasury/flag2.txt && \
    chown gov -R /treasury && \
    chmod 500 /treasury/ && chmod 400 /treasury/flag2.txt

ADD bailout /bailout
ADD libc.so.6 /lib/x86_64-linux-gnu/libc.so.6
RUN chown gov /bailout && \
    chmod 501 /bailout && \
    chmod u+s /bailout


ADD dotcom_market airbag start.sh /opt/


RUN adduser --no-create-home --disabled-password --gecos "" user
USER user

CMD ["/bin/bash", "/opt/start.sh"]

