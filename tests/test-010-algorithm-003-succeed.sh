#!/bin/sh
set -e

TD=`mktemp -d work-XXXXXXXXXXXXXX`
cd $TD
trap 'cd .. ; rm -rf $TD' EXIT

# determine algorithm to test based on file name
A=`basename $0 .sh | awk -F- '{print $4}' | sed -e 's/^0*//'`

# KSK
# See if this algorithm is supported by BIND dnssec tools
if dnssec-keygen -r /dev/urandom -a $A -b 1024 -n ZONE -f KSK . ; then
	true
else
	exit 33
fi

# See if this algorithm is supported by Net::DNS::SEC
if perl ../alg-support.pl K* ; then
	true
else
	echo "Installed Net::DNS::SEC does not appear to support algorithm $A"
	exit 33
fi

cat *.key | perl ../dnskey-to-ds.pl > trust

# ZSK
dnssec-keygen -r /dev/urandom -a $A -b 1024 -n ZONE .

dnssec-signzone -S -o . -f zone.signed -x ../zone.unsigned

perl ../../yazvs.pl -d -a trust -x zone.signed
