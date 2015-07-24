#!/bin/sh

. /etc/default/openmanage

CURRENT_DATE=$1
USERNAME=$2
PASSWORD=$3

DIAGNOSTICS_BASE=$OPENMANAGE_ROOT/tmp_diagnostics
DIAGNOSTICS_DIR=openmanage-diagnostics-$CURRENT_DATE
DIAGNOSTICS_BZ2=openmanage-diagnostics-$CURRENT_DATE.tar.bz2

rm -rf $DIAGNOSTICS_BASE
mkdir $DIAGNOSTICS_BASE
cd $DIAGNOSTICS_BASE
mkdir $DIAGNOSTICS_DIR

dpkg -l | grep '^ii' | awk '{print $2 "\t" $3}' > $DIAGNOSTICS_DIR/ubuntu_packages.txt
pip freeze > $DIAGNOSTICS_DIR/python_packages.txt

python $OPENMANAGE_ROOT/bin/diagnostics.py $DIAGNOSTICS_DIR $USERNAME $PASSWORD 2>&1 | tee $DIAGNOSTICS_DIR/diagnostics.log
wait

tar cjf $DIAGNOSTICS_BZ2 $DIAGNOSTICS_DIR