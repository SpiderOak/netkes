#!/bin/bash

# Restore script for the OpenManage Virtual Appliance.
# Today: restores OMVA configuration and database from a backup tarball.
# Tomorrow: fetches the OMVA restoration tarball from secure offsite backup.

. /etc/default/openmanage

# Stage Zero: Sanity-check the tarball
file $1 | grep 'gzip compressed data' 2>&1 1>/dev/null
if [ $? != 0 ]; then
    echo "Backup argument $1 not showing as a tarball properly.  Aborting." >&2
    exit
fi

# Stage One: Unzip the tarball.
tar xzf $1
pushd omva-backup

# Stage Two: move the configuration and keys back into place.
mkdir -p $SPIDEROAK_ESCROW_KEYS_PATH
mkdir -p $SPIDEROAK_ESCROW_LAYERS_PATH

cp -r omva-backup/keys/* $SPIDEROAK_ESCROW_KEYS_PATH
cp -r omva-backup/layers/* $SPIDEROAK_ESCROW_LAYERS_PATH

cp agent-config.json $OPENMANAGE_CONFIGDIR

# Stage Three: Re-load the DB SQL.
su postgres -c "psql -f db_dump.sql openmanage"

# Clean up.
popd
rm -r omva-backup
