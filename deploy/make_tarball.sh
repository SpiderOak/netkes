#!/bin/bash

# Usage information:
# make_tarball.sh <netkes repo root> <version number> <brand_id> ldap
set -e
set -x
set -o pipefail

pushd $1 > /dev/null
source_dir=`pwd`
popd > /dev/null

version=$2
management_files=$3

echo "Building OpenManage software suite from $source_dir"

deploy_dir=$source_dir/deploy
buildit_dir=$deploy_dir/openmanage

$HOME/netkes/upgrade/gather_resources.sh

if [ -f $deploy_dir/openmanage.tar.bz2 ]; then
    rm $deploy_dir/openmanage.tar.bz2
fi

if [ -e $buildit_dir ]; then
    rm -rf $buildit_dir
fi

mkdir $buildit_dir

# Setup the base.
mkdir $buildit_dir/bin

# XXX: Why not just rm *.pyc?
# XXX: Alan notes to use find
cp $source_dir/bin/*.{sh,py} $buildit_dir/bin

# Copy libraries
cp -r $source_dir/netkes $buildit_dir

# Copy over the django project
cp -r $source_dir/django $buildit_dir

# Copy fonts
cp -r $management_files/fonts $buildit_dir/django/apps/blue_management/blue_mgnt/static/fonts

# Setup destination git packages.
pushd $buildit_dir/django > /dev/null
./setup_git.sh $buildit_dir
popd > /dev/null #$buildit_dir/django

# Copy over the upgrades
cp -r $source_dir/upgrade $buildit_dir

# Setup the SQL package
mkdir $buildit_dir/sql
cp $source_dir/sql/*.sql $buildit_dir/sql

# Package the configuration files.
included_management="openmanage_defaults apt_list py_list agent_config.json.sample"
mkdir $buildit_dir/etc
for file in $included_management; do
    cp $source_dir/etc/$file $buildit_dir/etc
done


# Configure the runsv service.
mkdir -p $buildit_dir/etc/service/openmanage
mkdir -p $buildit_dir/etc/service/admin_console
cp $source_dir/etc/service/openmanage/run $buildit_dir/etc/service/openmanage
cp $source_dir/etc/service/admin_console/run $buildit_dir/etc/service/admin_console

# Tag it
echo "SpiderOak OpenManage $version" > $buildit_dir/etc/OpenManage_version.txt
echo "Built `date`" >> $buildit_dir/etc/OpenManage_version.txt
echo "Branch `git branch | grep '*' | sed 's/* //'`" >> $buildit_dir/etc/OpenManage_version.txt
echo "Commit `git log -n 1 --pretty=format:%H`" >> $buildit_dir/etc/OpenManage_version.txt

# Zip it
pushd $deploy_dir
tar cjf openmanage-$version.tar.bz2 openmanage
popd

cat $buildit_dir/etc/OpenManage_version.txt
