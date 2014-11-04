#!/bin/sh

. /etc/default/openmanage

CURRENT_DATE=$1

BACKUP_BASE=$OPENMANAGE_ROOT/tmp_backup
BACKUP_DIR=openmanage-backup-$CURRENT_DATE
BACKUP_BZ2=openmanage-backup-$CURRENT_DATE.tar.bz2

rm -rf $BACKUP_BASE
mkdir $BACKUP_BASE
cd $BACKUP_BASE
mkdir $BACKUP_DIR

cp -r $SPIDEROAK_ESCROW_LAYERS_PATH $BACKUP_DIR
cp -r $SPIDEROAK_ESCROW_KEYS_PATH $BACKUP_DIR
cp $OPENMANAGE_CONFIGDIR/agent_config.json $BACKUP_DIR
sudo -u postgres pg_dump openmanage > $BACKUP_DIR/openmanage.sql

tar cjf $BACKUP_BZ2 $BACKUP_DIR
