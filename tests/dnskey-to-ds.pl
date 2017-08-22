#!/usr/bin/perl

use strict;
use warnings;
use Net::DNS;
use Net::DNS::SEC;
use Getopt::Std;

my $opts = { 'd' => 2 };
getopts('d:', $opts) or die "usage: $0 [-d digtype]\n";

while (<>) {
        chomp;
        s/[\r\n]//g;
        next unless (/IN\s+DNSKEY/);
        my $dnskey = Net::DNS::RR->new($_);
        die "$_" unless $dnskey;
	if ($dnskey->revoke) {
		printf STDERR "skiping revoked key %d\n", $dnskey->keytag;
		next;
	}
        my $ds = Net::DNS::RR::DS->create($dnskey, digtype => $opts->{'d'});
        print $ds->plain . "\n";
}
