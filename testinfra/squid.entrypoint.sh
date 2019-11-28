#!/bin/sh

set -e

admin="administrator"
pass="P@ssw0rd"
keytab="/etc/squid/krb5.keytab"
krb5service="HTTP"

run_kadmin()
{
	printf '* Running kadmin command: %s\n' "$*"
	printf '%s\n' "$pass" | kadmin -p "$admin" "$@"
}

wait_on_kadmin()
{
	for i in `seq 1 10`; do
		printf .
		run_kadmin getprinc -terse "$admin" >/dev/null 2>&1 && { printf '\n'; return 0; }
		sleep 1
	done

	printf 'ERROR: Could not connect to admin server\n' >&2
	return 1
}

add_principal()
{
	princ="$1"
	kt="$2"

	printf '* Adding principal %s to %s\n' "$princ" "$kt"

	run_kadmin getprinc -terse "$princ" >/dev/null 2>&1 || \
		run_kadmin ank -randkey "$princ" || :
	run_kadmin ktadd -k "$kt" -norandkey "$princ"
}

canonify()
{
	name="$1"
	set -- `getent hosts "$name" 2>/dev/null`
	ipaddr="$1"
	test -n "$ipaddr" || return
	set -- `getent -s dns hosts "$ipaddr" 2>/dev/null`
	echo "$2"
}

wait_on_kadmin || exit

fullname="`hostname -f`"
srvprinc="$fullname"
test -z "$srvprinc" || add_principal "$krb5service/$srvprinc" "$keytab"

hostsrvprinc=`canonify "$fullname"`
test -z "$hostsrvprinc" || add_principal "$krb5service/$hostsrvprinc" "$keytab"

chown proxy: "$keytab"

exec "$@"
