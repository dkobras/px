#!/bin/sh

set -e

rm -f /etc/samba/smb.conf
samba-tool domain provision --domain=ADS --realm=ADS.EXAMPLE.COM --host-name=samba-dc --adminpass=P@ssw0rd --use-rfc2307

seq -f "adsuser%03g" 1 100 | xargs -n1 -t -i samba-tool user create {} P@ssw0rd

exec "$@"
