#!/bin/sh
mkdir -p results
errcnt=0
for f in test-*.sh; do
	k=`basename $f .sh`
	sh $f > results/$k.out 2>&1
	ret=$?

	if test $ret -eq 33 ; then
		echo "$k is UNSUPPORTED on this system"
		continue
	fi

	expect=`echo $k | awk -F. '{print $1}' | awk -F- '{print $NF}'`

	if test $ret -eq 0 && test $expect == "succeed" ; then
		echo "$k SUCCEEDED as expected"
	elif test $ret -eq 0 ; then
		echo "$k SUCCEEDED but was expected to FAIL"
		errcnt=`expr $errcnt + 1`
	elif test $ret -ne 0 && test $expect == "fail" ; then
		echo "$k FAILED as expected"
	else
		echo "$k FAILED but was expected to SUCCEED"
		errcnt=`expr $errcnt + 1`
	fi
done

if test $errcnt -eq 0 ; then
	echo "All tests passed"
	exit 0
else
	echo "$errcnt tests had errors"
	exit 1
fi
