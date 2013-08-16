#!/bin/bash

set -e
set -x
set -o pipefail

pushd $1 > /dev/null
source_dir=`pwd`
popd > /dev/null

version=$2

brand_identifier=$3
ldap=$4
echo "Building OpenManage software suite from $source_dir for $3"
if [ $4 == "ldap" ]; then
    echo "Enabling LDAP integration in this build."
fi

deploy_dir=$source_dir/deploy
buildit_dir=$deploy_dir/openmanage
rm $deploy_dir/openmanage.tar.bz2
rm -r $buildit_dir
mkdir $buildit_dir

# Setup the base.
mkdir $buildit_dir/bin
cp $source_dir/bin/*.{sh,py} $buildit_dir/bin 2> /dev/null

# Copy libraries
mkdir $buildit_dir/netkes
for package in `ls $source_dir/netkes`; do
    mkdir -p $buildit_dir/netkes/$package
    cp $source_dir/netkes/$package/*.py $buildit_dir/netkes/$package 2> /dev/null
done

# Copy LDAP over if necessary.
if [ $4 == "ldap" ]; then    
    mkdir $buildit_dir/netkes/account_mgr/user_source
    cp $source_dir/netkes/account_mgr/user_source/*.py $buildit_dir/netkes/account_mgr/user_source
fi

# Copy over the django project
cp -r $source_dir/django $buildit_dir

# Setup destination git packages.
pushd $buildit_dir/django > /dev/null
./setup_git.sh $buildit_dir
popd > /dev/null #$buildit_dir/django

# Setup the SQL package
mkdir $buildit_dir/sql
cp $source_dir/sql/*.sql $buildit_dir/sql

# Package the configuration files.
included_management="openmanage_defaults apt_list py_list agent_config.json.sample"
mkdir $buildit_dir/etc
for file in $included_management; do
    cp $source_dir/etc/$file $buildit_dir/etc
done

# Set the brand in the configuration
echo "OPENMANAGE_BRAND=$3" > $buildit_dir/etc/brand

# Configure the runsv service.
mkdir -p $buildit_dir/etc/service/openmanage
mkdir -p $buildit_dir/etc/service/admin_console
cp $source_dir/etc/service/openmanage/run $buildit_dir/etc/service/openmanage
cp $source_dir/etc/service/admin_console/run $buildit_dir/etc/service/admin_console

# Tag it
echo "SpiderOak OpenManage $version" > $buildit_dir/etc/OpenManage_version.txt
echo "Built `date`" >> $buildit_dir/etc/OpenManage_version.txt

# Zip it
pushd $deploy_dir > /dev/null
tar cjf openmanage.tar.bz2 openmanage
popd > /dev/null

cat $buildit_dir/etc/OpenManage_version.txt
