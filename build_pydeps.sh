#!/bin/bash

#common_opts="--verbose --force"
common_opts="--force"
maintainer="Daniel Kobras (Puzzle ITC) <kobras@puzzle-itc.de>"
excludes="*/__pycache__"
py_opts="-d python3 --python-bin python3 --python-pip pip3 --python-package-name-prefix python3 --python-install-lib /usr/lib/python3/dist-packages --python-install-bin /usr/bin"
deb_opts="--deb-priority optional"

pip_packages="colored dukpy tld"

for p in $pip_packages; do
	fpm $common_opts -m "$maintainer" -x "$excludes" $py_opts $deb_opts -s python -t deb "$p"
done

# Gooey requires dependency fixup
gooey_exclude="--python-disable-dependency wxpython --python-disable-dependency Pillow"
gooey_include="-d python3-pil -d python3-wxgtk4.0"
fpm $common_opts -m "$maintainer" -x "$excludes" $py_opts $dep_opts $gooey_exclude $gooey_include -s python -t deb Gooey

# pypac doesn't provide its source dist on pypi, but fpm cannot do without it
pypac_tmp_prefix="pypac-fpm-build"
pypac_tmp=`mktemp -d -t "$pypac_tmp_prefix".XXXXXXXXXX`

pypac_cleanup()
{
	test -n "$pypac_tmp" || return 0
	test -d "$pypac_tmp" || return 0
	case "$pypac_tmp" in
	*"$pypac_tmp_prefix"*) ;;
	*) return 0
	esac
	rm -rf "$pypac_tmp"
}

trap pypac_cleanup EXIT

workdir="$PWD"

cd "$pypac_tmp"

pypac_latest_url=`curl -s https://github.com/carsonyl/pypac/releases | sed -ne 's|.*href="\(/carsonyl/pypac/archive/.*tar.gz\)".*|https://github.com\1|p' | head -n1`
curl -sSL -O "$pypac_latest_url"

pypac_src_tar=`basename "$pypac_latest_url"`

mkdir src
mkdir pypac

cd src
tar xfvz ../"$pypac_src_tar"

cd pypac*
python3 setup.py sdist

mv dist/pypac*.tar.gz ../../pypac

cd ../..
rm -rf src

port=8000
python3 -m http.server --bind localhost "$port" &

cd "$workdir"
# pypac uses ~= comparison for tld and dukpy that fpm incorrectly translates into strict (=) versioned dependencies
# work around this flaw by excluding the auto-generated dependency, and injecting an unversioned one
fpm $common_opts -m "$maintainer" -x "$excludes" $py_opts $deb_opts --python-pypi http://localhost:"$port"/ --python-disable-dependency tld --python-disable-dependency dukpy -d python3-tld -d python3-dukpy -s python -t deb pypac

kill %1 || :
