#!/bin/bash

# Upgrade the OpenManage virtual appliance, given a tarball.
# 2011 SpiderOak, Inc. 

. /etc/default/openmanage

die() {
    echo $@ >&2
    exit 1
}

[ $# -eq 1 ] || die "Please specify the path to the upgrade tarball."
ziptype=`file -bi $1`
[ "$ziptype" == "application/x-bzip2; charset=binary" ] || die "$1 not a tarball!"

upgrade=`realpath "$1"`
sudo sv stop openmanage
pushd /opt
cp openmanage/etc/agent_config.json $HOME
sudo tar xjf $upgrade
sudo cp $HOME/agent_config.json /opt/openmanage/etc

popd
    
sudo sv start openmanage

echo "OpenManage upgrade complete."

