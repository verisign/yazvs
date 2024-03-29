#!/bin/sh
set -e

TD=`mktemp -d work-XXXXXXXXXXXXXX`
cd $TD
trap 'cd .. ; rm -rf $TD' EXIT

# KSK, trusted
dnssec-keygen -r /dev/urandom -a 8 -b 2048 -n ZONE -f KSK .
cat *.key | perl ../dnskey-to-ds.pl > trust

# ZSK
dnssec-keygen -r /dev/urandom -a 8 -b 2048 -n ZONE .

dnssec-signzone -S -o . -f zone.signed -x ../zone.unsigned

perl ../../yazvs.pl -d -a trust -x zone.signed
