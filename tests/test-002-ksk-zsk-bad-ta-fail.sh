#!/bin/sh
set -e

TD=`mktemp -d work-XXXXXXXXXXXXXX`
cd $TD
trap 'cd .. ; rm -rf $TD' EXIT

# KSK
dnssec-keygen -r /dev/urandom -a 8 -b 2048 -n ZONE -f KSK .

# clobber the trust anchor
cat *.key \
| perl ../dnskey-to-ds.pl \
| sed -e 's/[0-9a-f][0-9a-f]*$/1111111111111111111111111111111111111111111111111111111111111111/' \
> trust

# ZSK
dnssec-keygen -r /dev/urandom -a 8 -b 2048 -n ZONE .

dnssec-signzone -S -o . -f zone.signed -x ../zone.unsigned

perl ../../yazvs.pl -d -a trust -x zone.signed
