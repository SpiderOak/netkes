#!/bin/bash

set -e
set -x
set -o pipefail

MYDIR=$1

pushd $MYDIR/django

git clone https://github.com/jimfunk/django-postgresql-netfields.git

mkdir apps
pushd apps

git clone https://spideroak.com/dist/blue_management.git
git clone https://spideroak.com/dist/so_common.git
pushd blue_management

git submodule init
git submodule update

#cp -r blue_mgnt/templates/base ../so_common/templates

popd # blue_management
popd #apps

# Setup the static content
mkdir static

if [ -e static/blue_common ]; then
    rm static/blue_common
fi
cp -r apps/so_common/static static/blue_common

if [ -e apps/blue_management/blue_mgnt/templates/base ]; then
    rm apps/blue_management/blue_mgnt/templates/base
fi
cp -r apps/so_common/templates/base apps/blue_management/blue_mgnt/templates

popd # django

