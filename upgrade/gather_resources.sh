#!/bin/bash

if [ ! -d $source_dir ]; then
    echo "Must define \$source_dir to be the directory to install the packages, usually /path/to/netkes."
    exit
fi

cd $source_dir/upgrade

rm -rf resources
mkdir resources

cd resources

pip wheel -r ../requirements.txt 

sudo apt-get download libffi-dev
sudo apt-get download bash
