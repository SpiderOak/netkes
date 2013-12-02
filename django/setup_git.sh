#!/bin/bash

set -e
#set -x
set -o pipefail

pushd ${1:?}/django > /dev/null

echo
echo Downloading other git modules:
echo
git clone https://github.com/jimfunk/django-postgresql-netfields.git

mkdir apps
pushd apps > /dev/null

git clone https://spideroak.com/dist/blue_management.git
git clone https://spideroak.com/dist/so_common.git
pushd blue_management > /dev/null

echo Initializing submodules...
git submodule init
git submodule update

ln -s templates/base ../so_common/templates/base

popd > /dev/null # blue_management
popd > /dev/null #apps

# Setup the static content
mkdir static

ln -s /opt/openmanage/django/apps/so_common/static static/blue_common

popd > /dev/null

