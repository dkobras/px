FROM debian:latest as samba-dc

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get -y install samba \
                       winbind \
                       lsof \
                       procps \
                       tmux \
                       vim

COPY samba-dc.entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

ENTRYPOINT [ "/entrypoint.sh" ]

CMD [ "/usr/sbin/samba", "-F" , "-d", "1", "--debug-stderr" ]
