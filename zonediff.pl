#!/usr/bin/perl

# zonediff.pl
#
# "diff" zone files after excluding certain RR types
#

# Copyright (c) 2017, Verisign, Inc.
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
# 
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
# 
# * Neither the name of the copyright holder nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use strict;
use warnings;

use Net::DNS;
use Getopt::Long;
use File::Temp;

my $have_net_dns_zonefile = 0;
my $have_net_dns_zonefile_fast = 0;

if (eval "require Net::DNS::ZoneFile") {
	Net::DNS::ZoneFile->import;
	$have_net_dns_zonefile = 1;
} elsif (eval "require Net::DNS::ZoneFile::Fast") {
	Net::DNS::ZoneFile::Fast->import;
	$have_net_dns_zonefile_fast = 1;
} else {
	die "$0 requires either Net::DNS::ZoneFile or Net::DNS::ZoneFile::Fast to be installed\n";
}

my @ignore;

usage() unless GetOptions ("ignore=s" => \@ignore);

sub usage {
	print STDERR <<EOF;
ZoneDiff is a tool to view differences between two on-disk DNS zone files.
It can be instructed to omit certain record types (usually those related
to DNSSEC, which are not human-parseable and change frequently).

usage: $0 [--ignore=TYPE ...] old new
EOF
	exit(2);
}

sub read_zone {
	my $file = shift;
	my $rrs;
	if ($have_net_dns_zonefile_fast) {
		$rrs = Net::DNS::ZoneFile::Fast::parse(file=>$file);
	} else {
		my $zone = new Net::DNS::ZoneFile($file);
		die "$file: $!" unless $zone;
		while (my $rr = $zone->read) {
			push(@$rrs, $rr);
		}
	}
	@$rrs = canonicalize(@$rrs);
	return $rrs;
}

sub unixdiff {
	my $A = shift;
	my $B = shift;
	my $tempdir = File::Temp::tempdir("zonediff.XXXXXXXXXXX", CLEANUP=>1);
	my $oldfile = "$tempdir/old";
	output_zone($A, $oldfile);
	my $newfile = "$tempdir/new";
	output_zone($B, $newfile);
	print "\n";
	print "Diff Output\n";
	print '-' x 70 ."\n";
	system "diff -wu $oldfile $newfile";
	my $rc = $? >> 8;
	print "\n";
	return($rc);
}

sub output_zone {
	my $rrset = shift;
	my $out = shift;
	open(O, ">$out");
	select(O);
	foreach my $rr (@$rrset) {
		next if grep {$rr->type eq uc($_)} @ignore;
		$rr->print;
	}
	close(O);
	select(STDOUT);
}

sub rrsortfunc {
	my $namea = join('.',reverse(split/\./, $a->name));
	my $nameb = join('.',reverse(split/\./, $b->name));
	return $namea cmp $nameb unless $namea eq $nameb;
	return $a->type cmp $b->type unless $a->type eq $b->type;
	return $a->rdatastr cmp $b->rdatastr;
}

sub canonicalize {
	my @out;
	my $nsoa = 0;
	foreach my $rr (sort rrsortfunc @_) {
		next if 'SOA' eq $rr->type && $nsoa++ > 0;
		push(@out, $rr);
	}
	return @out;
}

usage() unless $#ARGV == 1;
my $A = read_zone(shift);
my $B = read_zone(shift);
exit unixdiff($A,$B);
