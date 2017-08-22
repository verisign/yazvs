#!/bin/sh
set -e

TD=`mktemp -d work-XXXXXXXXXXXXXX`
cd $TD
trap 'cd .. ; rm -rf $TD' EXIT

D=`basename $0 .sh | awk -F- '{print $5}' | sed -e 's/^0*//'`

dnssec-keygen -r /dev/urandom -a 8 -b 1024 -n ZONE -f KSK .

if cat *.key | perl ../dnskey-to-ds.pl -d $D K.* >/dev/null 2>&1 ; then
	true
else
	echo "Installed Net::DNS::SEC does not appear to support digest type $D"
	exit 33
fi
cat *.key | perl ../dnskey-to-ds.pl -d $D > trust

dnssec-keygen -r /dev/urandom -a 8 -b 1024 -n ZONE .

dnssec-signzone -S -o . -f zone.signed -x ../zone.unsigned

perl ../../yazvs.pl -d -a trust -x zone.signed
