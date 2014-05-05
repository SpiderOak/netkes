#!/bin/bash

# Standard  upgrade script for OMVAs.  We expect this script to be run
# via sudo.
#
# upgrade.sh upgradefile.tgz brand_id
#

set -x
#set -e
#set -o pipefail

usage(){
    cat << __EOF__
Usage:

upgrade.sh <upgradefile> [<brand_id>]

where <upgradefile> is a tarball, like openmanage-1.3.tar.bz2
and <brand_id> is the enterprise brand, imported if not specified and available.

Requirements:
Must be run as root, e.g. with sudo!
Only works with already installed MC version 1.2.2 or newer.
__EOF__
}

if [ $# -lt 1 ]; then
    usage
    exit
fi

if [ "$(id -u)" != "0" ]; then
    echo "Please run via sudo"
    exit 1
fi

. /etc/default/openmanage

UPDATE_TARBALL=`readlink -e $1`
if [ ! -n "$UPDATE_TARBALL" ]; then
    echo "The upgrade file could not be found.  Exiting."
    exit
fi
BRAND=${2:-$OPENMANAGE_BRAND} # Loaded indirectly from /etc/default/openmanage.
if [ ! -n "$BRAND" ]; then
    echo "The enterprise ID could not be loaded.  Exiting."
    exit
fi

echo "Starting upgrade using $UPDATE_TARBALL for enterprise $BRAND."
read -p "Press <Enter> to continue; <Ctrl>-C to abort."

CURRENT_DATE=$(date "+%y-%m-%d")


# Stop services.
for SERVICE in admin_console openmanage; do
    sv down $SERVICE || (echo "Unable to stop $SERVICE" ; exit)
done

# Move out old openmanage
mv /opt/openmanage /opt/openmanage.$CURRENT_DATE

pushd /opt
tar xjfv $UPDATE_TARBALL
popd #/opt

echo "updated tarball"

# Bring over configuration into the new stuff.
cp /opt/openmanage.$CURRENT_DATE/etc/agent_config.json /opt/openmanage/etc

random_string="$(< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c 64;echo;)"
secret_key="export DJANGO_SECRET_KEY=\"$random_string\""
echo $secret_key >> /opt/openmanage/etc/openmanage_defaults 

# Set the brand in the configuration
echo "OPENMANAGE_BRAND=$BRAND" > /opt/openmanage/etc/brand

echo "Updating database..."
/opt/openmanage/upgrade/apply_sql.sh
echo "Running additional update scripts..."

sudo bash -c "PYTHONPATH=/opt/openmanage python /opt/openmanage/upgrade/apply_scripts.py"

apt-get -y remove python-crypto
pip install -r /opt/openmanage/upgrade/requirements.txt

# Restart services
for SERVICE in openmanage admin_console; do
    sv up $SERVICE
done

echo "Upgrade complete!"
