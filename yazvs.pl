#!/usr/bin/perl

# yazvs.pl
#
# yazvs.pl is a utility that validates and compares DNSSEC-signed zones
# before they are published.
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
use Net::DNS::SEC;
use Getopt::Std;
use File::Temp;
use Time::Local;
use POSIX;
use Switch;
use Digest;

my %opts = (e => 10);
getopts('A:a:cdre:t:m:n:uxyC:Z', \%opts) || usage();
usage() unless @ARGV;

# Net::DNS version 1.23 is required for ZONEMD implementation that
# matches RFC 8976
#
Net::DNS->VERSION('1.23') if $opts{Z};

my $now = time;
my $zone_name = undef;
my $zone_name_printable = undef;
my $candidate_serial = undef;
my $candidate_rrset = undef;
my $current_rrset = undef;
my @nsset = ();
my @ds_anchors = read_anchors($opts{a}) if $opts{a};
my $soa = undef;
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

my $have_lwp_useragent = 0;
my $have_xml_simple = 0;
my $xml_anchors = undef;
if ($opts{A}) {
	if (eval 'require LWP::UserAgent') {
		LWP::UserAgent->import;
		$have_lwp_useragent = 1;
	}
	if (eval 'require XML::Simple') {
		XML::Simple->import;
		$have_xml_simple = 1;
	}
	die "$0 -A option requires LWP::UserAgent and XML::Simple.  Make sure both are installed.\n"
		unless ($have_lwp_useragent && $have_xml_simple);
	$xml_anchors = read_xml_anchors($opts{A});
}

use constant {
	Valid	=> 0,
	Expiring => 1,
	Invalid => 2,
};

candidate(shift);
unless ($opts{x}) {
	current();
	internaldiff();
	unixdiff() if $opts{u};
}

print "\nValidation for $zone_name_printable $candidate_serial ",
	$nproblems ? 'FAILED' : 'PASSED',
	", $nproblems problems\n";
exit($nproblems ? 1 : 0);

##############################################################################

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
\t-A url\t\tURL containing trust anchors
\t-x\t\tDon't diff with current zone
\t-y\t\tDon't check RRSIGs
\t-e days\t\tcomplain about RRSIGs that expire within days days
\t-t key\t\tTSIG filename or hash string
\t-n keyname\tTSIG name if not otherwise given
\t-m master\thidden master nameserver
\t-C zonefile\tload current zone from file instead of axfr
\t-Z\t\tverify ZONEMD record
EOF
	exit(2);
}

sub rrsig_str {
	my $rrsig = shift;
	"RRSIG=". $rrsig->keytag;
}

sub dnskey_str {
	my $dnskey = shift;
	"DNSKEY=". $dnskey->keytag. ($dnskey->sep ? '/SEP' : '');
}


sub candidate {
	my $file = shift;
	my $rrset = read_zone_file ($file);
	my @dnskeys = ();
	my @ksks = ();
	my $zonemds = ();
	my $rrsigs;
	@$rrset = canonicalize(@$rrset);
	foreach my $rr (@$rrset) {
		$zone_name_printable = $zone_name = $rr->name if 'SOA' eq $rr->type;
		$candidate_serial = $rr->serial if 'SOA' eq $rr->type;
		push(@dnskeys, $rr) if 'DNSKEY' eq $rr->type;
	}
	$zone_name_printable = 'root' if '.' eq $zone_name_printable;
	print "Crypto Validation of $zone_name_printable $candidate_serial\n";
	print '-' x 70 ."\n";
	ok("Parsed ". int(@$rrset). " RRs from $file");
	debug(sprintf "%d DNSKEYs in zone", int(@dnskeys));
	foreach my $rr (@dnskeys) {
		debug(dnskey_str($rr));
	}
	@ksks = trusted_ksks(remove_revoked($rrset, @dnskeys));
	foreach my $rr (@$rrset) {
		next unless lc($zone_name) eq lc($rr->name);
		push(@nsset, $rr->nsdname) if 'NS' eq $rr->type;
		$zonemds->{$rr->algorithm}->{rr} = $rr if 'ZONEMD' eq $rr->type;
	}
	my $x = 0;
	if (@ksks) {
		ok(int(@ksks). " trusted KSKs found");
	} elsif ($opts{a}) {
		problem("No trusted KSKs found");
	} elsif ($opts{y}) {
		debug("Trusted KSKs not required due to -y");
	} else {
		problem("You didn't supply a trust anchor.  Use -a option");
	}
	foreach my $rr (@$rrset) {
		next unless $rr->type eq 'RRSIG';
		next unless lc($rr->name) eq lc($zone_name);
		next unless $rr->typecovered eq 'DNSKEY';
		$x++ if Valid == sig_is_valid($rr, \@dnskeys, \@ksks);
	}
	if ($opts{y}) {
		debug("DNSKEY RRset validation not required due to -y");
	} elsif (0 == $x) {
		problem("Cannot validate DNSKEY RRset with KSKs");
	} else {
		ok("Apex DNSKEY RRset validated");
	}
	if ($opts{Z}) {
		if (keys %$zonemds) {
			ok(int(keys %$zonemds). " ZONEMD records found with digest types: " . join(',', keys %$zonemds));
			foreach my $dt (keys %$zonemds) {
				switch ($dt) {
					case 1 {
						$zonemds->{$dt}->{md} = Digest->new('SHA-384');
					}
					case 2 {
						$zonemds->{$dt}->{md} = Digest->new('SHA-512');
					}
					else {
						problem("Unsupported ZONEMD digest type $dt");
						delete $zonemds->{$dt};
					}
				}
			}
		} else {
			problem("No ZONEMD records found");
		}
	}
	my $goodsigs = 0;
	my $badsigs = 0;
	my $expsigs = 0;
	foreach my $rr (@$rrset) {
		foreach my $dt (keys %$zonemds) {
			next if 'ZONEMD' eq $rr->type && $rr->name eq $zone_name;
			next if 'RRSIG' eq $rr->type && 'ZONEMD' eq $rr->typecovered && $rr->name eq $zone_name;
			debug("ZONEMD add: ". $rr->string);
			debug(unpack('H*', $rr->canonical));
			$zonemds->{$dt}->{md}->add($rr->canonical);
		}
		next unless 'RRSIG' eq $rr->type;
		if ($rrsigs->{$rr->name}->{$rr->typecovered}->{$rr->keytag}) {
			problem("Duplicate RRSIG for ".$rr->name." ".$rr->typecovered." keytag ".$rr->keytag);
		}
		$rrsigs->{$rr->name}->{$rr->typecovered}->{$rr->keytag} = 1;
		next if $opts{y};
		switch (sig_is_valid($rr, $rrset, \@dnskeys)) {
			case Valid	{ $goodsigs++; }
			case Expiring	{ $expsigs++; }
			case Invalid	{ $badsigs++; }
		}
	}
	if ($opts{y}) {
		ok("RRSIG processing skipped with -y option");
	} else {
		ok_or_problem(!$expsigs, "$expsigs expiring RRSIGs found");
		debug(sprintf "Time to first RRSIG expiry: %.1f days", $minexpiry / 86400);
		ok_or_problem(!$badsigs, "$badsigs bad RRSIGs found");
		ok_or_problem($goodsigs, "$goodsigs good RRSIGs found");
	}
	foreach my $dt (keys %$zonemds) {
		my $givn = $zonemds->{$dt}->{rr}->digest;
		my $calc = $zonemds->{$dt}->{md}->hexdigest;
		debug("Given ZONEMD $givn");
		debug("Calc  ZONEMD $calc");
		ok_or_problem($givn eq $calc, "ZONEMD type $dt matches", "ZONEMD type $dt does NOT match");
	}
	$candidate_rrset = $rrset;
}

sub current {
	my $res = Net::DNS::Resolver->new;
	my @rrset;
	print "\n";
	print "Comparison to current zone\n";
	print '-' x 70 ."\n";
	#
	# Load from file if given
	# 
	if ($opts{C}) {
		my $t_rrset = read_zone_file($opts{C});
		@rrset = @$t_rrset;
	} else {
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
		my $axfr_name = $zone_name;
		$axfr_name = '.' if '' eq $zone_name;
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
			problem("Failed to AXFR $zone_name_printable zone");
			exit(1);
		}
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
		my $rrtype = $t;
		$rrtype = 'DNSKEY' if 'KSK' eq $t;
		$rrtype = 'DNSKEY' if 'ZSK' eq $t;
		my @a = ();
		foreach my $rr (@$candidate_rrset) {
			next unless ($rr->type eq $rrtype);
			next if 'KSK' eq $t && !$rr->sep;
			next if 'ZSK' eq $t && $rr->sep;
			debug("candidate has $t with keytag ". $rr->keytag);
			push(@a, lc($rr->string));
		}
		my @b = ();
		foreach my $rr (@$current_rrset) {
			next unless ($rr->type eq $rrtype);
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
	my @files = ();
	my $output_file;
	my $tempdir = File::Temp::tempdir("$zone_name_printable.tmp.XXXXXXXXXXX", CLEANUP=>$opts{d}?0:1);
	$output_file = "$tempdir/$zone_name_printable.current";
	output_zone($current_rrset, $output_file);
	push(@files, $output_file);
	$output_file = "$tempdir/$zone_name_printable.". ($opts{r} ? 'former' : 'candidate');
	output_zone($candidate_rrset, $output_file);
	push(@files, $output_file);
	@files = reverse @files if $opts{r};
	print "\n";
	print "Diff Output (excluding RRSIG/NSEC/NSEC3 records)\n";
	print '-' x 70 ."\n";
	system "diff -iwu ". join(' ', @files);
	print "\n";
	debug("Zone files left in $tempdir");	# true only if -d
}

sub remove_revoked {
	my $rrset = shift;
	my @dnskeys = @_;
	#
	# Take out the revoked keys
	#
	my @revoked_dnskeys = ();
	foreach my $rrsig (@$rrset) {
		next unless 'RRSIG' eq $rrsig->type;
		next unless 'DNSKEY' eq $rrsig->typecovered;
		next unless lc($rrsig->name) eq lc($zone_name);
        	foreach my $dnskey (@dnskeys) {
			next unless $rrsig->keytag == $dnskey->keytag;
			if ($dnskey->revoke && Valid == sig_is_valid($rrsig, \@dnskeys, [ $dnskey ])) {
				ok(dnskey_str($dnskey). " is REVOKED");
				push @revoked_dnskeys, $dnskey;
			}
		}
	}
	return @dnskeys unless @revoked_dnskeys;
	my @non_revoked = ();
	foreach my $dnskey (@dnskeys) {
		push @non_revoked, $dnskey unless grep {$_ == $dnskey} @revoked_dnskeys;
	}
	return @non_revoked;
}

sub trusted_ksks {
	my @ds_verified_keys = ();
        foreach my $dnskey (@_) {
                foreach my $ds (@ds_anchors) {
                        my $v = $ds->verify($dnskey);
                        push(@ds_verified_keys, $dnskey) if $v;
                        my $msg = sprintf("DS=%d %s %s",
                                $ds->keytag,
                                $v ? 'verifies' : 'does not verify',
                                dnskey_str($dnskey),
                                );
			$v ? ok($msg) : debug($msg);
                        last if $v;
                }
        }
	#
	# if there are no XML anchors then just return the DS verified anchors
	#
	return @ds_verified_keys unless $xml_anchors;
	my @xml_verified_keys;
	problem("XML anchors are for zone '". $xml_anchors->{Zone}. "' but candidate is zone '$zone_name'")
		unless lc($xml_anchors->{Zone}) eq lc($zone_name);
	foreach my $dnskey (@ds_verified_keys) {
		foreach my $id (keys %{$xml_anchors->{KeyDigest}}) {
			my $h = $xml_anchors->{KeyDigest}->{$id};
			# this time format matches IANA root-anchors.xml
			my $now_strftime = POSIX::strftime('%Y-%m-%dT%H:%M:%S+00:00', gmtime(time));
			next if $h->{validFrom} ge $now_strftime;
			my $ds = new Net::DNS::RR(join(' ',
				$xml_anchors->{Zone},
				'DS',
				$h->{KeyTag},
				$h->{Algorithm},
				$h->{DigestType},
				$h->{Digest}));
			my $v = $ds->verify($dnskey);
                        push(@xml_verified_keys, $dnskey) if $v;
                        my $msg = sprintf("XML Anchor ID '%s' %s %s",
                                $id,
                                $v ? 'verifies' : 'does not verify',
                                dnskey_str($dnskey),
                                );
			$v ? ok($msg) : debug($msg);
			last if $v;
		}
	}
	return @xml_verified_keys;
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
	my $tt_exp = $exp - $now;	# seconds
	$minexpiry = $tt_exp if $tt_exp < $minexpiry;
	if ($tt_exp < ($opts{e} * 86400)) {
		my $msg = sprintf "%s/%s/%d RRSIG expires in %.1f days",
			$rrsig->name,
			$rrsig->typecovered,
			$rrsig->keytag,
			($exp - $now) / 86400;
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
	#print "Validating ". $rrsig->name. "/". $rrsig->typecovered. " ". rrsig_str($rrsig). "\n";
	foreach my $key (@$dnskeys) {
		next unless $key->keytag == $rrsig->keytag;
		if ($key->revoke) {
			next unless 'DNSKEY' eq $rrsig->typecovered;
		}
		#print "   checking key ". $key->keytag."\n";
		if ($rrsig->verify(\@data, $key)) {
			debug(rrsig_str($rrsig). " + ". dnskey_str($key). " signs ". $rrsig->name. "/". $rrsig->typecovered. " RRset");
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
	my $namea = join('.',reverse(split/\./, lc($a->name)));
	my $nameb = join('.',reverse(split/\./, lc($b->name)));
	return $namea cmp $nameb unless $namea eq $nameb;
	return Net::DNS::Parameters::typebyname($a->type) <=> Net::DNS::Parameters::typebyname($b->type) unless $a->type eq $b->type;
	return $a->rdata cmp $b->rdata;
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
	my $file = shift;
	my $n = 0;
	my @anchors = ();
	if (open(F, $file)) {
		while (<F>) {
			chomp;
			s/;.*//;
			next unless /./;
			$n++;
			my $rr = Net::DNS::RR->new($_);
			next unless $rr;
			# might want to check rr->name here but zone_name isn't defined yet.
			next unless 'DS' eq $rr->type || 'DNSKEY' eq $rr->type;
			if ('DNSKEY' eq $rr->type) {
				$rr = Net::DNS::RR::DS->create($rr, digtype => 2);
			}
			unless (defined $rr->algorithm and $rr->keytag != 0) {
				warn "Invalid $rr->type record on line $n of $file\n";
				sleep(3);
				next;
			}
			push(@anchors, $rr) if $rr;
		}
		close(F);
	}
	debug("Read ". int(@anchors). " trust anchors from ". $file);
	@anchors;
}

sub read_xml_anchors {
	my $url = shift;
	my $ua = LWP::UserAgent->new;
	$ua->agent("yazvs.pl");
	my $req = HTTP::Request->new(GET => $url);
	my $res = $ua->request($req);
	die $res->status_line unless $res->is_success;
	die "Expected '$url' content-type to be text/xml but got ".$res->content_type unless 'text/xml' eq $res->content_type;
	my $xs = XML::Simple->new;
	my $ref = $xs->XMLin($res->content, ForceArray => ['KeyDigest']);
	return $ref;
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
	my $msg_ok = shift;
	my $msg_pr = shift;
	if ($ok) {
		ok($msg_ok);
	} else {
		problem($msg_pr ? $msg_pr : $msg_ok);
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
