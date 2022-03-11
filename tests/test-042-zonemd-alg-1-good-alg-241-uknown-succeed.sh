#!/bin/sh
set -e

TD=`mktemp -d work-XXXXXXXXXXXXXX`
cd $TD
#trap 'cd .. ; rm -rf $TD' EXIT

# KSK, trusted
KSK=$(dnssec-keygen -r /dev/urandom -a 8 -b 2048 -n ZONE -f KSK .)
cat $KSK.key | perl ../dnskey-to-ds.pl > trust

# ZSK
ZSK=$(dnssec-keygen -r /dev/urandom -a 8 -b 2048 -n ZONE .)

dnssec-signzone -S -o . -f zone.signed -x ../zone.unsigned
ldns-zone-digest -p 1,1 -p 1,241 -c -z $ZSK.private -o zone.hashed . zone.signed

perl ../../yazvs.pl -Z -d -a trust -x zone.hashed
