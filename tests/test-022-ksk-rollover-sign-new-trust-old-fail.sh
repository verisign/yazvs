#!/bin/sh
set -e

TD=`mktemp -d work-XXXXXXXXXXXXXX`
cd $TD
trap 'cd .. ; rm -rf $TD' EXIT

# old KSK, "retired"
dnssec-keygen -a 8 -b 2048 -n ZONE -f KSK -I now .

# only old key is trusted
cat *.key | perl ../dnskey-to-ds.pl > trust

# new KSK, used for signing, but not trusted
dnssec-keygen -a 8 -b 2048 -n ZONE -f KSK .

# ZSK
dnssec-keygen -a 8 -b 2048 -n ZONE .

dnssec-signzone -S -o . -f zone.signed -x ../zone.unsigned

perl ../../yazvs.pl -d -a trust -x zone.signed
