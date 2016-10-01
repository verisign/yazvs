#!/usr/bin/perl

# yazvs.pl
#
# yazvs.pl is a utility that validates and compares DNSSEC-signed zones
# before they are published.
#

# Copyright (C) 2016 VeriSign, Inc
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
use Net::DNS::SEC;
use Getopt::Std;
use File::Temp;
use Time::Local;
use Switch;

my %opts = (e => 10);
getopts('a:cdre:t:m:n:ux', \%opts) || usage();
usage() unless @ARGV;

my $NOW = time;
my $ZONE_NAME = undef;
my $ZONE_NAME_PRINTABLE = undef;
my $CANDIDATE_SERIAL = undef;
my $candidate_rrset = undef;
my $current_rrset = undef;
my @nsset = ();
my @ds_anchors = read_ds_anchors() if $opts{a};
my @dnskey_anchors = read_dnskey_anchors() if $opts{a};
my $nproblems = 0;
my $minexpiry = 86400*365*10;

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

my $have_list_compare = 0;
my $have_set_object = 0;

if (eval "require List::Compare") {
	List::Compare->import;
	$have_list_compare = 1;
} elsif (eval "require Set::Object") {
	Set::Object->import;
	$have_set_object = 1;
} else {
	die "$0 requires either List::Compare or Set::Object to be installed\n";
}

use constant {
	Valid	=> 0,
	Expiring => 1,
	Invalid => 2,
};

sub usage {
print STDERR <<"EOF";
YAZVS is a utility that compares an on-disk DNSSEC-signed zone file to
the currently-being-served zone data.  It performs the following steps:

  1) Validates DNSKEY RRsets and signatures (RRSIG) records in the
     on-disk zone file.
  2) Retreives the current zone data from a master server with AXFR.
  3) Outputs a diff of the two copies of the zone, omitting any RRSIG
     NSEC, and NSEC3 records.

usage: $0 -c -d -r -u -x -a file -e days -t key -n keyname -m master zonefile
\t-c\t\tzonefile is already "clean" so use alternate parsing
\t-d\t\tenable debugging
\t-r\t\treverse (axfr is current, disk file is old)
\t-u\t\tunix diff of zone files at the end
\t-a file\t\tfile containing trust anchors
\t-x\t\tDon't diff with current zone
\t-e days\t\tcomplain about RRSIGs that expire within days days
\t-t key\t\tTSIG filename or hash string
\t-n keyname\tTSIG name if not otherwise given
\t-m master\thidden master nameserver
EOF
	exit(2);
}


sub candidate {
	my $file = shift;
	my $rrset = read_zone_file ($file);
	my @dnskeys = ();
	my @ksks = ();
	my $rrsigs;
	@$rrset = canonicalize(@$rrset);
	foreach my $rr (@$rrset) {
		$ZONE_NAME_PRINTABLE = $ZONE_NAME = $rr->name if 'SOA' eq $rr->type;
		$CANDIDATE_SERIAL = $rr->serial if 'SOA' eq $rr->type;
		push(@dnskeys, $rr) if 'DNSKEY' eq $rr->type;
	}
	$ZONE_NAME_PRINTABLE = 'root' if '' eq $ZONE_NAME_PRINTABLE;
	print "Crypto Validation of $ZONE_NAME_PRINTABLE $CANDIDATE_SERIAL\n";
	print '-' x 70 ."\n";
	ok("Parsed ". int(@$rrset). " RRs from $file");
	@ksks = @dnskey_anchors ? @dnskey_anchors : trusted_ksks(@dnskeys);
	foreach my $rr (@$rrset) {
		push(@nsset, $rr->nsdname) if 'NS' eq $rr->type && lc($ZONE_NAME) eq lc($rr->name);
	}
	my $x = 0;
	if (@ksks) {
		ok(int(@ksks). " trusted KSKs found");
	} elsif ($opts{a}) {
		problem("No trusted KSKs found");
	} else {
		problem("You didn't supply a trust anchor.  Use -a option");
	}
	foreach my $rr (@$rrset) {
		next unless $rr->type eq 'RRSIG';
		next unless lc($rr->name) eq lc($ZONE_NAME);
		next unless $rr->typecovered eq 'DNSKEY';
		$x++ if Valid == sig_is_valid($rr, \@dnskeys, \@ksks);
	}
	unless ($x) {
		problem("Cannot validate DNSKEY RRset with KSKs");
	} else {
		ok("Apex DNSKEY RRset validated");
	}
	my $goodsigs = 0;
	my $badsigs = 0;
	my $expsigs = 0;
	foreach my $rr (@$rrset) {
		next unless 'RRSIG' eq $rr->type;
		if ($rrsigs->{$rr->name}->{$rr->typecovered}->{$rr->keytag}) {
			problem("Duplicate RRSIG for ".$rr->name." ".$rr->typecovered." keytag ".$rr->keytag);
		}
		$rrsigs->{$rr->name}->{$rr->typecovered}->{$rr->keytag} = 1;
		switch (sig_is_valid($rr, $rrset, \@dnskeys)) {
			case Valid	{ $goodsigs++; }
			case Expiring	{ $expsigs++; }
			case Invalid	{ $badsigs++; }
		}
	}
	ok_or_problem(!$expsigs, "$expsigs expiring RRSIGs found");
	debug(sprintf "Time to first RRSIG expiry: %.1f days", $minexpiry / 86400);
	ok_or_problem(!$badsigs, "$badsigs bad RRSIGs found");
	ok_or_problem($goodsigs, "$goodsigs good RRSIGs found");
	$candidate_rrset = $rrset;
}

sub current {
	my $res = Net::DNS::Resolver->new;
	my @rrset;
	print "\n";
	print "Comparison to current zone\n";
	print '-' x 70 ."\n";
	#
	# set TSIG key if necessary
	#
	if ($opts{t}) {
		my ($n,$t) = get_tsig_key($opts{t});
		debug("TSIG name=$n, key=$t");
		$res->tsig($n,$t);
	}
	#
	# if Master was given on the command line...
	#
	if ($opts{m}) {
		@nsset = ();
		push(@nsset, $opts{m});
	}
	#
	# Attempt AXFR from authoritative nameservers
	#
	my $axfr_name = $ZONE_NAME;
	$axfr_name = '.' if '' eq $ZONE_NAME;
	foreach my $ns (@nsset) {
		#debug("Attempting AXFR of $axfr_name from $ns");
 		$res->nameserver($ns);
		@rrset = $res->axfr($axfr_name);
		if (@rrset) {
			ok("Received ". int(@rrset). " RRs from $ns");
			last;
		}
		debug($ns. ": ". $res->errorstring);
	}
	unless (@rrset) {
		problem("Failed to AXFR $ZONE_NAME_PRINTABLE zone");
		exit(1);
	}
	my $serial = undef;
	foreach my $rr (@rrset) {
		$serial = $rr->serial if 'SOA' eq $rr->type;
	}
	if ($serial) {
		ok("Current serial $serial");
	} else {
		problem("No SOA in AXFR data");
	}
	@rrset = canonicalize(@rrset);
	$current_rrset = \@rrset;
}

sub internaldiff {
	foreach my $t (qw(KSK ZSK RRSIG DS)) {
		my $T = $t;
		$T = 'DNSKEY' if 'KSK' eq $t;
		$T = 'DNSKEY' if 'ZSK' eq $t;
		my @a = ();
		foreach my $rr (@$candidate_rrset) {
			next unless ($rr->type eq $T);
			next if 'KSK' eq $t && !$rr->sep;
			next if 'ZSK' eq $t && $rr->sep;
			debug("candidate has $t with keytag ". $rr->keytag);
			push(@a, lc($rr->string));
		}
		my @b = ();
		foreach my $rr (@$current_rrset) {
			next unless ($rr->type eq $T);
			next if 'KSK' eq $t && !$rr->sep;
			next if 'ZSK' eq $t && $rr->sep;
			debug("current   has $t with keytag ". $rr->keytag);
			push(@b, lc($rr->string));
		}
		my $added;
		my $removed;
		my $unchanged;
		if ($have_list_compare) {
			my $lc = List::Compare->new(\@a, \@b);
			$added = int($lc->get_Lonly);
			$removed = int($lc->get_Ronly);
			$unchanged = int($lc->get_intersection);
		} else {
			my $sa = Set::Object->new(@a);
			my $sb = Set::Object->new(@b);
			$added = $sa->difference($sb)->size;
			$removed = $sb->difference($sa)->size;
			$unchanged = $sa->intersection($sb)->size;
		}
		diff("$t $added added, $removed removed, $unchanged unchanged");
	
	}
}

sub unixdiff {
	my @FILES = ();
	my $OF;
	my $TEMPDIR = File::Temp->tempdir("$ZONE_NAME.tmp.XXXXXXXXXXX", CLEANUP=>$opts{d}?0:1);
	$OF = "$TEMPDIR/$ZONE_NAME_PRINTABLE.current";
	output_zone($current_rrset, $OF);
	push(@FILES, $OF);
	$OF = "$TEMPDIR/$ZONE_NAME.". ($opts{r} ? 'former' : 'candidate');
	output_zone($candidate_rrset, $OF);
	push(@FILES, $OF);
	@FILES = reverse @FILES if $opts{r};
	print "\n";
	print "Diff Output (excluding RRSIG/NSEC/NSEC3 records)\n";
	print '-' x 70 ."\n";
	system "diff -wu ". join(' ', @FILES);
	print "\n";
	debug("Zone files left in $TEMPDIR");	# true only if -d
}

candidate(shift);
unless ($opts{x}) {
	current();
	internaldiff();
	unixdiff() if $opts{u};
}

print "\nValidation for $ZONE_NAME_PRINTABLE $CANDIDATE_SERIAL ",
	$nproblems ? 'FAILED' : 'PASSED',
	", $nproblems problems\n";
exit($nproblems ? 1 : 0);

sub trusted_ksks {
	my @verified_keys = ();
        foreach my $dnskey (@_) {
                foreach my $ds (@ds_anchors) {
                        my $v = $ds->verify($dnskey);
                        push(@verified_keys, $dnskey) if $v;
                        my $msg = sprintf("DS=%d %s DNSKEY=%d%s",
                                $ds->keytag,
                                $v ? 'verifies' : 'does not verify',
                                $dnskey->keytag, $dnskey->sep ? '/SEP' : '',
                                );
			debug($msg);
                        last if $v;
                }
        }
	return @verified_keys;
}

sub sig_is_valid {
	my $rrsig = shift;
	my $rrset = shift;
	my $dnskeys = shift;
	my @data = ();
	my $exp = timestamp_to_epoch($rrsig->sigexpiration);
	unless ($exp) {
		debug("failed to get expiration time from\n". $rrsig->string);
		return Invalid;
	}
	my $tt_exp = $exp - $NOW;	# seconds
	$minexpiry = $tt_exp if $tt_exp < $minexpiry;
	if ($tt_exp < ($opts{e} * 86400)) {
		my $msg = sprintf "%s/%s/%d RRSIG expires in %.1f days",
			$rrsig->name,
			$rrsig->typecovered,
			$rrsig->keytag,
			($exp - $NOW) / 86400;
		debug($msg);
		return Expiring;
	}
	foreach my $rr (@$rrset) {
		next unless $rr->type eq $rrsig->typecovered;
		next unless $rr->name eq $rrsig->name;
		push(@data, $rr);
	}
	unless (@data) {
		debug("Didn't find any ". $rrsig->name. "/". $rrsig->typecoverred. " RRs");
		return Invalid;
	}
	#print "Validating ". $rrsig->name. "/". $rrsig->typecovered. " RRSIG\n";
	foreach my $key (@$dnskeys) {
		#print "   checking key ". $key->keytag."\n";
		if ($rrsig->verify(\@data, $key)) {
			debug("RRSIG/". $rrsig->keytag. " + DNSKEY/". $key->keytag. " signs ". $rrsig->name. "/". $rrsig->typecovered. " RRset");
			return Valid;
		}
		#debug($rrsig->vrfyerrstr);
	}
	debug("No DNSKEYs validate the ". $rrsig->name. "/". $rrsig->keytag. "/". $rrsig->typecovered. " RRSIG");
	return Invalid;
}

sub timestamp_to_epoch {
	my $ts = shift;
	unless ($ts =~ /^(\d\d\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)/) {
		debug("bad timestamp: $ts");
		return undef;
	}
	return timegm ($6,$5,$4,$3,$2-1,$1-1900);
}

sub output_zone {
	my $rrset = shift;
	my $out = shift;
	open(O, ">$out");
	select(O);
	foreach my $rr (@$rrset) {
		next if 'RRSIG' eq $rr->type;
		next if 'NSEC' eq $rr->type;
		next if 'NSEC3' eq $rr->type;
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

sub get_tsig_key {
	#
	# returns an array which is the args to Net::DNS::Resolver->tsig();
	#
	my $keyarg = shift;
	my $keyname = $opts{n};
	my $keydata = undef;
	#
	# First, assume keyarg is the name of a file that has been
	# generated by BIND's dnssec-keygen
	#
	if (open(F, $keyarg)) {
		while(<F>) { $keydata = $1 if /Key:\s+(\S+)/; }
		close(F);
		unless ($keyname) {
			# assume keyfile generated by BIND dnssec-keygen
			# e.g., Kfoo.+157+35697.private
			$keyname = $1 if $keyarg =~ /^K([^\.]+)\./;
		}
		return ($keyname,$keydata) if $keyname && $keydata;
	}
	#
	# Next assume its a named.conf format key
	#
	if (open(F, $keyarg)) {
		while(<F>) {
			$keyname = $1 if /^key\s+(\S+)/;
			$keydata = $1 if /secret\s+"([^"]+)"/;
		}
		close(F);
		return ($keyname,$keydata) if $keyname && $keydata;
	}
	#
	# Next assume its a file that only contains the key data on a single line
	# and the name of the key is either given separately on the command line
	# or is the name of the file.
	#
	if (open(F, $keyarg)) {
		$keydata = <F>;
		chomp $keydata;
		close(F);
		$keyname = $keyarg unless $keyname;
		return ($keyname,$keydata) if $keyname && $keydata;
	}
	#
	# Lastly, assume the keydata is in the command line argument and
	# the key name is given separately on the command line
	#
	return ($keyname,$keyarg);
}

sub read_anchors {
	my $type = shift;
	my $file = shift;
	my $N = 0;
	my @anchors = ();
	if (open(F, $file)) {
		while (<F>) {
			chomp;
			$N++;
			my $rr = Net::DNS::RR->new($_);
			next unless $rr->type eq $type;
			unless (defined $rr->algorithm and $rr->keytag != 0) {
				warn "Invalid $type record on line $N of $file\n";
				sleep(3);
				next;
			}

			push(@anchors, $rr) if $rr;
		}
		close(F);
	}
	debug("Read ". int(@anchors). " $type trust anchors from ". $file);
	@anchors;
}

sub read_zone_file {
	my $file = shift;
	my $rrs;
	if ($opts{c}) {
		die "$file: $!" unless open (F, $file);
		my $line = 0;
		while (<F>) {
			chomp;
			$line++;
			s/\s*;.*//;
			next unless (/./);
			my $rr = Net::DNS::RR->new($_);
			die "Failed to parse line $line of $file\n" unless $rr;
			push(@$rrs, $rr);
		}
		close(F);
	} elsif ($have_net_dns_zonefile_fast) {
		$rrs = Net::DNS::ZoneFile::Fast::parse(file=>$file);
	} else {
		my $zone = new Net::DNS::ZoneFile($file);
		die "$file: $!" unless $zone;
		while (my $rr = $zone->read) {
			push(@$rrs, $rr);
		}
	}
	return $rrs;
}

sub read_ds_anchors {
	read_anchors('DS', $opts{a});
}

sub read_dnskey_anchors {
	read_anchors('DNSKEY', $opts{a});
}

sub ok {
	my $msg = shift;
	print "OK: $msg\n";
}

sub problem {
	my $msg = shift;
	print "PROBLEM: $msg\n";
	$nproblems++;
}

sub ok_or_problem {
	my $ok = shift;
	my $msg = shift;
	if ($ok) {
		ok($msg);
	} else {
		problem($msg);
	}
}

sub diff {
	my $msg = shift;
	print "DIFF: $msg\n";
}

sub debug {
	my $msg = shift;
	print "DEBUG: $msg\n" if $opts{d};
}
