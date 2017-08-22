#!/usr/bin/perl
use strict;
use warnings;
use Net::DNS;
use Net::DNS::SEC;

my $pub;
my $prv;

foreach my $f (@ARGV) {
	if ($f =~ /\.private$/) {
		$prv = $f;
	} else {
		open(F, $f) or die "$f: $!";
		while (<F>) {
        		chomp;
        		s/[\r\n]//g;
        		next unless (/IN\s+DNSKEY/);
        		$pub = Net::DNS::RR->new($_);
        		die "$_" unless $pub;
		}
		close(F);
	}
}
unless ($pub && $prv) {
	die "usage: $0 K*.key K*.private\n";
}

my $rrsig = create Net::DNS::RR::RRSIG([$pub], $prv);
$rrsig->print;

