# YAZVS &mdash; Yet Another Zone Validation Script

_yazvs.pl_ is one of the utilities that Verisign uses daily to
validate new versions of the _root_ and _arpa_ zones
before they are published to the distribution masters.

It performs the following steps:

1. Read a _candidate_ zone file from disk
1. Validate KSKs using a locally configured trust anchor
1. Validate ZSKs using KSKs
1. Validate RRSIGs using ZSKs
1. Retrieve the _current_ zone data via AXFR
1. Print a summary of the number of KSKs, ZSKs, DS, and RRSIG records that have changed
1. Optionally produce a Unix diff of the two zones, excluding RRSIG/NSEC/NSEC3 records

```
Crypto Validation of root 2010071501
----------------------------------------------------------------------
OK: 2 trusted KSKs found
OK: Apex DNSKEY RRset validated
OK: 0 expiring RRSIGs found
OK: 0 bad RRSIGs found
OK: 299 good RRSIGs found

Comparison to current zone
----------------------------------------------------------------------
OK: Received 3655 RRs from 10.0.0.1
OK: Current serial 2010071500
DIFF: KSK 1 added, 1 removed, 0 unchanged
DIFF: ZSK 1 added, 1 removed, 0 unchanged
DIFF: RRSIG 1 added, 1 removed, 298 unchanged
DIFF: DS 0 added, 0 removed, 10 unchanged

Validation for root 2010071501 PASSED, 0 problems
```

## Usage
```
usage: yazvs.pl -c -d -r -u -x -a file -e days -t key -n keyname -m master zonefile
        -c              zonefile is already "clean" so use alternate parsing
        -d              enable debugging
        -r              reverse (axfr is current, disk file is old)
        -u              unix diff of zone files at the end
        -a file         file containing trust anchors
        -A url          URL containing trust anchors
        -x              Don't diff with current zone
        -y              Don't check RRSIGs
        -e days         complain about RRSIGs that expire within days days
        -t key          TSIG filename or hash string
        -n keyname      TSIG name if not otherwise given
        -m master       hidden master nameserver
        -C zonefile     load current zone from file instead of axfr
        -Z              verify ZONEMD record
```

The default value for the _-e_ option is 10 days.

The trust anchor file (_-a_ option) may contain either
DNSKEY or DS records as they would appear in a zone file.

If the _-m_ option is omitted, AXFR will be attempted
from the authoritative nameservers given in the zone file.

If the _-A_ option is given, the script fetches the URL
expected to contain XML-formatted trust anchors, such as the one
IANA publishes for the root zone.  The in-zone KSKs are then further
validated against the XML trust anchors.

If the _-x_ option is given, the script only verifies input 
zone and omits any comparison to the current zone.

If the _-Z_ option is given, the script verifies ZONEMD
records found in the zone.

## Requirements

_yazvs.pl_ uses the
[Net::DNS](http://search.cpan.org/perldoc?Net::DNS),
[Net::DNS::SEC](http://search.cpan.org/perldoc?Net::DNS::SEC),
[Net::DNS::ZoneFile::Fast](http://search.cpan.org/perldoc?Net::DNS::ZoneFile::Fast) or
[Net::DNS::ZoneFile](http://search.cpan.org/perldoc?Net::DNS::ZoneFile), and
[List::Compare](http://search.cpan.org/perldoc?List::Compare) or
[Set::Object](http://search.cpan.org/perldoc?Set::Object)
perl modules.

The following modules are required if the _-A_ option is used:
[LWP](http://search.cpan.org/perldoc?LWP),
[XML::Simple](http://search.cpan.org/perldoc?XML::Simple).

## Zone Diff

_zonediff.pl_ is a similar utility that produces a Unix diff of two
zone files after optionally excluding certain record types.

## Copyright and License

yazvs.pl and zonediff.pl are Copyright 2017 by Verisign, Inc and
licensed under the terms of the BSD 3-Clause License.
