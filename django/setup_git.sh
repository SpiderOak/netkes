#!/bin/bash

pushd /opt/openmanage/django

git clone https://github.com/adamcik/django-postgresql-netfields.git

mkdir apps
pushd apps

git clone https://spideroak.com/dist/blue_management.git
git clone https://spideroak.com/dist/so_common.git
pushd blue_management

git submodule init
git submodule update

ln -s templates/base ../so_common/templates/base

popd # blue_management
popd #apps

# Setup the static content
mkdir static

ln -s /opt/openmanage/django/apps/so_common/static /opt/openmanage/django/static/blue_common
ln -s /opt/openmanage/django/apps/so_common/templates/base /opt/openmanage/django/apps/blue_management/blue_mgnt/templates/base

popd # /opt/openmanage/django

