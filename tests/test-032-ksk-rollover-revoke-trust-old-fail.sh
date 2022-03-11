#!/bin/sh
set -e

TD=`mktemp -d work-XXXXXXXXXXXXXX`
cd $TD
trap 'cd .. ; rm -rf $TD' EXIT

# old KSK, trusted
dnssec-keygen -r /dev/urandom -a 8 -b 2048 -n ZONE -f KSK -I now .
KN=`basename *.key .key`
cat *.key | perl ../dnskey-to-ds.pl > trust

# revoke old KSK
dnssec-revoke -r $KN

# new KSK
dnssec-keygen -r /dev/urandom -a 8 -b 2048 -n ZONE -f KSK .

# ZSK
dnssec-keygen -r /dev/urandom -a 8 -b 2048 -n ZONE .

dnssec-signzone -S -o . -f zone.signed -x ../zone.unsigned

perl ../../yazvs.pl -d -a trust -x zone.signed
