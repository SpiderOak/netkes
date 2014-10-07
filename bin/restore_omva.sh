#!/bin/bash

# Restore script for the OpenManage Virtual Appliance.
# Today: restores OMVA configuration and database from a backup tarball.
# Tomorrow: fetches the OMVA restoration tarball from secure offsite backup.

. /etc/default/openmanage

set -x

# Stage Zero: Sanity-check the tarball
file $1 | grep 'bzip2 compressed data' 2>&1 1>/dev/null
if [ $? != 0 ]; then
    echo "Backup argument $1 not showing as a tarball properly.  Aborting." >&2
    exit
fi

# Stage One: Unzip the tarball.
BACKUP_BASE=$OPENMANAGE_ROOT/tmp_backup

cd $BACKUP_BASE

tar xjfv $1
pushd openmanage-backup*

# Stage Two: move the configuration and keys back into place.
mkdir -p $SPIDEROAK_ESCROW_KEYS_PATH
mkdir -p $SPIDEROAK_ESCROW_LAYERS_PATH

cp -r keys/* $SPIDEROAK_ESCROW_KEYS_PATH
cp -r layers/* $SPIDEROAK_ESCROW_LAYERS_PATH

cp agent_config.json $OPENMANAGE_CONFIGDIR

# Stage Three: Re-load the DB SQL.
sudo -u postgres psql -f /opt/openmanage/bin/resources/recreate_openmanage.sql
sudo -u postgres psql --single-transaction --pset pager=off -f openmanage.sql openmanage 

# We already have keys so we don't need to run first setup
touch /opt/openmanage/etc/.ran_firstsetup

# Clean up.
popd
rm -r openmanage-backup*
sudo sv restart admin_console
