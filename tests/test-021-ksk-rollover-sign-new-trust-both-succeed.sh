#!/bin/sh
set -e

TD=`mktemp -d work-XXXXXXXXXXXXXX`
cd $TD
trap 'cd .. ; rm -rf $TD' EXIT

# old KSK, "retired"
dnssec-keygen -r /dev/urandom -a 8 -b 2048 -n ZONE -f KSK -I now .

# new KSK, usable for signing
dnssec-keygen -r /dev/urandom -a 8 -b 2048 -n ZONE -f KSK .

# both keys trusted
cat *.key | perl ../dnskey-to-ds.pl > trust

# ZSK
dnssec-keygen -r /dev/urandom -a 8 -b 2048 -n ZONE .

dnssec-signzone -S -o . -f zone.signed -x ../zone.unsigned

perl ../../yazvs.pl -d -a trust -x zone.signed
