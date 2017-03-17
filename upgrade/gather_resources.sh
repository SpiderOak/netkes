#!/bin/bash

if [ ! -d $source_dir ]; then
    echo "Must define \$source_dir to be the directory to install the packages, usually /path/to/netkes."
    exit
fi

cd $source_dir/upgrade

rm -rf resources
mkdir resources

cd resources

pip install --download=. pip==1.4.1
pip install --download=. Django==1.8.14
pip install --download=. pytz==2013.8
pip install --download=. py-bcrypt==0.4
pip install --download=. pycrypto==2.4.1
pip install --download=. cffi==0.8.2
pip install --download=. six==1.6.1
pip install --download=. pycparser==2.10
pip install --download=. pynacl==0.2.3
pip install --download=. inflection==0.3.1
pip install --download=. requests==2.13.0

sudo apt-get download libffi-dev
sudo apt-get download bash
sudo apt-get download anacron
