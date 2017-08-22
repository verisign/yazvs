#!/bin/sh
set -e

TD=`mktemp -d work-XXXXXXXXXXXXXX`
cd $TD
trap 'cd .. ; rm -rf $TD' EXIT

# old KSK
dnssec-keygen -a 8 -b 2048 -n ZONE -f KSK -I now .
KN=`basename *.key .key`

# new KSK
dnssec-keygen -a 8 -b 2048 -n ZONE -f KSK .
cat *.key | perl ../dnskey-to-ds.pl > trust

dnssec-revoke -r $KN

# ZSK
dnssec-keygen -a 8 -b 2048 -n ZONE .

dnssec-signzone -S -o . -f zone.signed -x ../zone.unsigned

perl ../../yazvs.pl -d -a trust -x zone.signed
