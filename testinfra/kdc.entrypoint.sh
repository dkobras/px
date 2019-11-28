#!/bin/sh

ls -la /var/lib/krb5kdc
df /var/lib/krb5kdc

if ! test -e /var/lib/krb5kdc/principal; then
	printf "*** Initializing new KDC database ***\n"
	printf "%s\n%s\n" "P@ssw0rd" "P@ssw0rd" | kdb5_util create -s && \
	kadmin.local ank -pw P@ssw0rd administrator && \
	seq -f "testuser%03g" 1 100 | xargs -n 1 kadmin.local ank -pw P@ssw0rd && \
	seq -f "testuser%03g/admin" 1 100 | xargs -n 1 kadmin.local ank -pw P@ssw0rd
fi

exec "$@"
