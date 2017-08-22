#!/bin/sh
set -e

TD=`mktemp -d work-XXXXXXXXXXXXXX`
cd $TD
trap 'cd .. ; rm -rf $TD' EXIT

# KSK
dnssec-keygen -a 8 -b 2048 -n ZONE -f KSK .
cat *.key | perl ../dnskey-to-ds.pl > trust

# ZSK
dnssec-keygen -a 8 -b 2048 -n ZONE .

dnssec-signzone -S -o . -f - -x ../zone.unsigned \
| sed -e 's/127\.0\.0\.1/127.127.127.127/g' \
> zone.signed

perl ../../yazvs.pl -d -a trust -x zone.signed
