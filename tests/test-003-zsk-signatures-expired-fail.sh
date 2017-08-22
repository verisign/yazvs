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

NOW=`date +%s`
SIG_START_T=`expr $NOW - 2592000`
SIG_END_T=`expr $NOW - 1296000`
SIG_START=`date --date @$SIG_START_T '+%Y%m%d%H%M%S'`
SIG_END=`date --date @$SIG_END_T '+%Y%m%d%H%M%S'`

dnssec-signzone -S -o . -f zone.signed -x -s $SIG_START -e $SIG_END -P ../zone.unsigned

perl ../../yazvs.pl -d -a trust -x zone.signed
