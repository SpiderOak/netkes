#!/bin/bash

if [ ! -d $source_dir ]; then
    echo "Must define \$source_dir to be the directory to install the packages, usually /path/to/netkes."
    exit
fi

cd $source_dir/upgrade

rm -rf resources
mkdir resources

cd resources

# History:
# 
#  1.3: pip 1.4.1; Django 1.5.5

pip install --download=. pip==1.4.1
pip install --download=. Django==1.5.5
pip install --download=. pytz==2013.8
pip install --download=. pynacl==0.2.3
pip install --download=. py-bcrypt==0.4

apt-get -d install libffi-dev
cp /var/cache/apt/archives/libffi-dev_* .
