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

upgrade.sh <version>

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

VERSION=$1

UPDATE_TARBALL="openmanage-$VERSION.tar.bz2"
if [ ! -n "$UPDATE_TARBALL" ]; then
    echo "The upgrade file could not be found.  Exiting."
    exit
fi

echo "Starting upgrade using $UPDATE_TARBALL."

CURRENT_DATE=$(date "+%y-%m-%d-%T")


# Stop services.
for SERVICE in admin_console openmanage; do
    sv down $SERVICE || (echo "Unable to stop $SERVICE" ; exit)
done

# Move out old openmanage
mv /opt/openmanage /opt/openmanage.$CURRENT_DATE

tar xjfv $UPDATE_TARBALL -C /opt
ln -s /opt/openmanage-$VERSION /opt/openmanage
echo "updated tarball"

# Bring over configuration into the new stuff.
cp /opt/openmanage.$CURRENT_DATE/etc/agent_config.json /opt/openmanage/etc

random_string="$(< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c 64;echo;)"
secret_key="export DJANGO_SECRET_KEY=\"$random_string\""
echo $secret_key >> /opt/openmanage/etc/openmanage_defaults 

echo "Updating database..."
/opt/openmanage/upgrade/apply_sql.sh

echo "Running additional update scripts..."
sudo bash -c "PYTHONPATH=/opt/openmanage python /opt/openmanage/upgrade/apply_scripts.py"

apt-get -y remove python-crypto

find /opt/openmanage/upgrade/resources/ -name '*.deb' | xargs dpkg -i

cat /opt/openmanage/upgrade/requirements.txt | xargs pip install

# Restart services
for SERVICE in openmanage admin_console; do
    sv up $SERVICE
done

# Backup VM
sudo /opt/openmanage/bin/backup_omva.sh
echo "Backup complete"

# Set VM version
python /opt/openmanage/bin/set_version.py $VERSION

echo "Upgrade complete!"
