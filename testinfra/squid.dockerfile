FROM debian:latest as squid-noauth

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get -y install lsof \
                       procps \
                       squid \
                       squidclient \
                       tmux \
                       vim

RUN printf 'SQUID_ARGS="-YC -d1 --foreground -f $CONFIG"\n' > /etc/default/squid && \
    printf 'http_access allow all\n' > /etc/squid/conf.d/99_acl.conf

EXPOSE 3128

CMD [ "service", "squid", "start" ]

FROM squid-noauth as squid-spnego

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get -y install gss-ntlmssp \
                       krb5-user

COPY squid.entrypoint.sh /entrypoint.sh

RUN printf '[libdefaults]\n\tdefault_realm = %s\n\tforwardable = true\n\n[realms]\n\t%s = {\n\t\tkdc = %s\n\t\tadmin_server = %s\n\t}\n' EXAMPLE.COM EXAMPLE.COM kdc-example kadmin-example > /etc/krb5.conf && \
    printf 'auth_param negotiate program /usr/lib/squid/negotiate_kerberos_auth -k /etc/squid/krb5.keytab -s GSS_C_NO_NAME\nacl auth proxy_auth REQUIRED\n' > /etc/squid/conf.d/80_spnego.conf && \
    printf 'http_access deny !auth\nhttp_access allow auth\nhttp_access deny all\n' > /etc/squid/conf.d/99_acl.conf && \
    chmod +x /entrypoint.sh

ENTRYPOINT [ "/entrypoint.sh" ]

CMD [ "service", "squid", "start" ]

FROM squid-noauth as squid-ntlm

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get -y install samba winbind

COPY squid-ntlm.entrypoint.sh /entrypoint.sh

RUN printf '[global]\n\tsecurity = ads\n\trealm = %s\n\tworkgroup = %s\n' "ADS.EXAMPLE.COM" "ADS" > /etc/samba/smb.conf && \
    printf 'auth_param ntlm program /usr/bin/ntlm_auth --helper-protocol=squid-2.5-ntlmssp\nacl auth proxy_auth REQUIRED\n' > /etc/squid/conf.d/80_spnego.conf && \
    printf 'http_access deny !auth\nhttp_access allow auth\nhttp_access deny all\n' > /etc/squid/conf.d/99_acl.conf && \
    chmod +x /entrypoint.sh

ENTRYPOINT [ "/entrypoint.sh" ]

CMD [ "service", "squid", "start" ]

