#!/bin/bash

# Upgrade the OpenManage virtual appliance, given a tarball.
# 2011 SpiderOak, Inc. 

set -e
set -x
set -o pipefail

. /etc/default/openmanage

die() {
    echo $@ >&2
    exit 1
}

# Some sanity checking
[ $# -eq 1 ] || die "Please specify the path to the upgrade tarball."
ziptype=`file -bi $1`
[ "$ziptype" == "application/x-bzip2; charset=binary" ] || die "$1 not a tarball!"

upgrade=`realpath "$1"`

# Stop services
sudo sv stop openmanage
sudo sv stop admin_console

# Push the binary updates.
pushd /opt
# Create a backup tarball of the existing openmanage installation
now=$(date +%s)
tar cjfv ~/openmanage-$now-last.tar.bz2 openmanage
mv openmanage openmanage.back
sudo tar xjf $upgrade
sudo cp openmanage.back/etc/agent_config.json openmanage/etc/agent_config.json
sudo grep 'DJANGO_SECRET_KEY' openmanage.back/etc/openmanage_defaults >> openmanage/etc/openmanage_defaults
rm -r openmanage.back

# Apply SQL updates
pushd upgrade
python apply_sql.py
popd #upgrade
popd #/opt
    
sudo sv start openmanage
sudo sv start admin_console


echo "OpenManage upgrade complete."

