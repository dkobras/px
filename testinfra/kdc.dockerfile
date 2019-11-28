FROM debian:latest as kdc-base

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get -y install krb5-admin-server \
                       krb5-kdc \
                       lsof \
                       procps \
                       tmux \
                       vim

RUN printf '[libdefaults]\n\tdefault_realm = %s\n\tforwardable = true\n\n[realms]\n\t%s = {\n\t\tkdc = %s\n\t\tadmin_server = %s\n\t}\n' EXAMPLE.COM EXAMPLE.COM kdc-example kadmin-example > /etc/krb5.conf && \
    printf 'administrator xe\n*/admin *\n' > /etc/krb5kdc/kadm5.acl && \
    rm -f /var/lib/krb5kdc/principal*

COPY kdc.conf /etc/krb5kdc/kdc.conf

FROM kdc-base as kdc-example

COPY kdc.entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT [ "/entrypoint.sh" ]

CMD [ "/usr/sbin/krb5kdc", "-n" ]

EXPOSE 88 

FROM kdc-base as kadmin-example

CMD [ "/usr/sbin/kadmind", "-nofork" ]

EXPOSE 464 749
