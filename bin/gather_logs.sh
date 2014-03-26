#!/bin/sh

CURRENT_DATE=$1

LOG_BASE=/opt/openmanage/tmp_logs
LOG_DIR=$LOG_BASE/openmanage-logs-$CURRENT_DATE
LOG_BZ2=$LOG_BASE/openmanage-logs-$CURRENT_DATE.tar.bz2

mkdir $LOG_BASE
mkdir $LOG_DIR

cp -r /var/log/admin_console/ $LOG_DIR
cp -r /var/log/omva/ $LOG_DIR

tar cjf $LOG_BZ2 $LOG_DIR

#rm -rf $LOG_DIR
#rm -rf $LOG_BZ2
