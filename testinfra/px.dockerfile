#FROM debian:latest as px-build-pyinstaller
FROM ubuntu:bionic as px-build-pyinstaller

WORKDIR /src

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get -y install libkrb5-dev \
                       libssl-dev \
                       python3-pip \
                       python3-gssapi \
                       python3-psutil \
                       python3-ntlm-auth \
                       python3-netaddr \
                       python3-keyring \
                       python3-keyrings.alt \
                       python3-requests \
                       python3-certifi \
                       python3-altgraph \
                       python3-numpy \
                       python3-pil \
                       python3-wxgtk4.0 \
                       && \
    apt-get clean && \
    pip3 install --no-cache-dir gssapi \
                                ntlm-auth \
                                netaddr \
                                keyring \
                                keyrings.alt \
                                psutil \
                                pyinstaller \
                                pypac && \
    pip3 install --no-cache-dir --no-deps Gooey

COPY px.py build.sh ./

RUN chmod +x px.py build.sh && \
    ./build.sh

FROM ubuntu:xenial as px-build-debian-pyinstaller

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get -y install debhelper \
                       dpkg-dev \
                       git \
                       git-buildpackage \
                       libkrb5-dev \
                       libssl-dev \
                       python3-pip \
                       virtualenv && \
    apt-get clean

WORKDIR /src/px

COPY ./ ./

RUN rm -rf include/ share/ local/ lib/ bin/ && \
    DEB_BUILD_OPTIONS="nocheck nogui pyinstaller" dpkg-buildpackage -d -us -uc

FROM ubuntu:bionic as px-build-debian-native

WORKDIR /src

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get -y install libkrb5-dev \
                       libssl-dev \
                       python3 \
                       python3-all \
                       python3-setuptools \
                       python3-pip \
                       python3-gssapi \
                       python3-psutil \
                       python3-ntlm-auth \
                       python3-netaddr \
                       python3-keyring \
                       python3-keyrings.alt \
                       python3-requests \
                       python3-certifi \
                       python3-altgraph \
                       python3-numpy \
                       python3-pil \
                       python3-wxgtk4.0 && \
    apt-get clean

RUN DEBIAN_FRONTEND=noninteractive \
    apt-get -y install curl \
                       debhelper \
                       dpkg-dev \
                       python3-pip \
                       ruby \
                       ruby-dev \
                       virtualenv && \
    gem install fpm

COPY build_pydeps.sh ./

RUN /bin/sh -x build_pydeps.sh && \
    dpkg --install *.deb

WORKDIR /src/px

COPY ./debian/ ./debian/
COPY HISTORY.txt LICENSE.txt px.ico px.ini px.py px.service README.md setup.py ./

RUN DEB_BUILD_OPTIONS="nocheck" dpkg-buildpackage -us -uc && \
    dpkg --info ../px-proxy_*.deb && \
    dpkg --contents ../px-proxy_*.deb

#FROM ubuntu:xenial as px
FROM ubuntu:bionic as px

WORKDIR /src

## Alternative 1: use custom build (and skip the next RUN stanza below)
#COPY --from=px-build-pyinstaller /src/dist/px /usr/bin/px-proxy
## Alternative 2: use pyinstaller-based Debian package
#COPY --from=px-build-debian-pyinstaller /src/px-proxy_*_amd64.deb /src
## Alternative 3: use full set of Debian packages
COPY --from=px-build-debian-native /src/*.deb /src/
RUN apt-get update && \
    dpkg --install --force-depends /src/*.deb && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get -y install -f

EXPOSE 3128

CMD [ "/usr/bin/px-proxy", "--debug", "--gateway" ]

FROM px as px-test

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get -y install krb5-user \
                       python3 \
                       python3-keyring \
                       python3-keyrings.alt && \
    apt-get clean

RUN mkdir -p /root/.local/share/python_keyring/ && \
    printf '[backend]\ndefault-keyring=keyrings.alt.file.PlaintextKeyring\n' > /root/.local/share/python_keyring/keyringrc.cfg && \
    printf '[libdefaults]\n\tdefault_realm = %s\n\tforwardable = true\n\trdns = false\n\n[realms]\n\t%s = {\n\t\tkdc = %s\n\t\tadmin_server = %s\n\t}\n' EXAMPLE.COM EXAMPLE.COM kdc-example kadmin-example > /etc/krb5.conf

COPY testinfra/testproxy.pac /src/proxy.pac

COPY testinfra/px.entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

ENTRYPOINT [ "/entrypoint.sh" ]

CMD [ "/usr/bin/px-proxy", "--debug", "--gateway", "--pac=/src/proxy.pac", "--username=ADS\\adsuser001" ]
