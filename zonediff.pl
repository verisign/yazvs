#!/usr/bin/perl

# zonediff.pl
#
# "diff" zone files after excluding certain RR types
#

# Copyright (C) 2010 VeriSign, Inc
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

use strict;
use warnings;

use Net::DNS;
use Net::DNS::ZoneFile::Fast;
use Getopt::Long;
use File::Temp;

my @IGNORE;

usage() unless GetOptions ("ignore=s" => \@IGNORE);

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
	my $rrset = Net::DNS::ZoneFile::Fast::parse(file=>$file);
	@$rrset = canonicalize(@$rrset);
	return $rrset;
}

sub unixdiff {
	my $A = shift;
	my $B = shift;
	my @FILES = ();
	my $OF;
	my $TEMPDIR = File::Temp->tempdir("zonediff.XXXXXXXXXXX", CLEANUP=>1);
	$OF = "$TEMPDIR/old";
	output_zone($A, $OF);
	push(@FILES, $OF);
	$OF = "$TEMPDIR/new";
	output_zone($B, $OF);
	push(@FILES, $OF);
	print "\n";
	print "Diff Output\n";
	print '-' x 70 ."\n";
	system "diff -wu ". join(' ', @FILES);
	print "\n";
}

sub output_zone {
	my $rrset = shift;
	my $out = shift;
	open(O, ">$out");
	select(O);
	foreach my $rr (@$rrset) {
		next if grep {$rr->type eq uc($_)} @IGNORE;
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
unixdiff($A,$B)
