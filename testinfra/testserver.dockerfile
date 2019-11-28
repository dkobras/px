FROM debian:latest as testserver

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get -y install python && \
    apt-get clean

COPY testserver.py /srv

EXPOSE 8000

CMD [ "/srv/testserver.py" ]
