#!/bin/bash

# Backup script for the OpenManage Virtual Appliance.
# Today: Generates a tarball with the important-to-backup data.
# Tomorrow: This will eventually send the tarball automatically for secure offsite backup.

. /etc/default/openmanage

backup_workspace=$HOME/omva-backup
backup_date=`date -u +%Y%m%d_%H%M`
# Stage one: prepare the destination
mkdir -p $backup_workspace

# Stage two: Collect the trivial stuff.
cp $OPENMANAGE_CONFIGDIR/agent_config.json $backup_workspace
cp -r $SPIDEROAK_ESCROW_KEYS_PATH $backup_workspace
cp -r $SPIDEROAK_ESCROW_LAYERS_PATH $backup_workspace

# Stage three: collect the DB contents.
su postgres -c "pg_dump openmanage" > $backup_workspace/db_dump.sql

pushd $HOME
tar czf $HOME/omva-backup-$backup_date.tar.gz ./omva-backup
rm -r $backup_workspace
popd
