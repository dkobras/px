#!/bin/sh

set -e

krb5_princ='testuser001'
ntlm_princ='ADS\adsuser001'
pw='P@ssw0rd'

krb5_creds()
{
	for i in `seq 1 10`; do
		printf .
		printf '%s\n' "$pw" | kinit "$krb5_princ" 2> /dev/null && break
		sleep 1
	done

	klist
}

ntlm_creds()
{
	printf '%s\n' "$pw" | python3 -m keyring set Px "$ntlm_princ"
}

krb5_creds
ntlm_creds

exec "$@"
