#!/bin/sh

set -e

admin="administrator"
pass="P@ssw0rd"

for i in `seq 1 10`; do
	printf '%s\n' "P@ssw0rd" | net ads join -U "$admin" && break
	printf .
	sleep 5
done

net ads testjoin

winbindd -D
wbinfo -t

adduser proxy winbindd_priv

exec "$@"
