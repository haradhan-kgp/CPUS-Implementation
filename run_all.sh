#!/bin/sh
# Usage: PV=/path/to/proverif ./run_all.sh     (tested with ProVerif 2.00)
PV=${PV:-proverif}
for f in main fs eph; do
  echo "=== cpus_$f.pv"
  $PV cpus_$f.pv 2>&1 | grep -E "^RESULT"
done
