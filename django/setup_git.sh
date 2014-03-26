#!/bin/bash

set -e
set -x
set -o pipefail

pushd ${1:?}/django

git clone https://github.com/jimfunk/django-postgresql-netfields.git

pwd
# Setup the static content
mkdir static

ln -s /opt/openmanage/django/apps/blue_management/blue_mgnt/static static/blue_mgnt

popd

