#!/bin/bash

if [ ! -d $source_dir ]; then
    echo "Must define \$source_dir to be the directory to install the packages, usually /path/to/netkes."
    exit
fi

cd $source_dir/upgrade

rm -rf resources
mkdir resources

cd resources

if [ ! -d /tmp/gather_resources/archives/partial ]; then
    mkdir -p /tmp/gather_resources/archives/partial
fi

LIBFFI_DEPS=`apt-cache depends libffi-dev |
    grep 'Depends' |
    cut -d: -f2 |
    tr -d ' ' |
    grep -v dpkg |
    grep -v install-info |
    xargs -d "\n"`

apt-get -y -d -o dir::cache=/tmp/gather_resources -o Debug::NoLocking=1 --reinstall install libffi-dev $LIBFFI_DEPS
cp /tmp/gather_resources/archives/*.deb .
rm -rf /tmp/gather_resources

# History:
# 
#  1.3: pip 1.4.1; Django 1.5.5

pip install --download=. pip==1.4.1
pip install --download=. Django==1.5.5
pip install --download=. pytz==2013.8
pip install --download=. pycrypto==2.4.1
pip install --download=. py-bcrypt==0.4
pip install --download=. cffi==0.8.2
pip install --download=. six==1.6.1
pip install --download=. pycparser==2.10

# NOTE: this fails loudly, but it should download the tarball,
# which is all we care about
echo "Downloading PyNaCl..."
pip install --download=. PyNaCl==0.2.3 2>&1 >/dev/null || true
[ -e ./PyNaCl-0.2.3.tar.gz ] && echo "Done."
