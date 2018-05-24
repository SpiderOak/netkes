#!/bin/bash

# Standard  upgrade script for OMVAs.  We expect this script to be run
# via sudo.
#
# upgrade.sh upgradefile.tgz brand_id
#

set -x
set -e
set -o pipefail

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
if ! cmp -s /opt/openmanage.$CURRENT_DATE/etc/agent_config.json /opt/openmanage/etc/agent_config.json
then
    echo "copying agent_config.json"
    cp /opt/openmanage.$CURRENT_DATE/etc/agent_config.json /opt/openmanage/etc
else 
    echo "agent_config.json hasn't changed"
fi

rsync /opt/openmanage.$CURRENT_DATE/etc/keys/* /opt/openmanage/etc/keys

echo "Setting django secret key"
random_string="$(< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c 64;echo;)"
secret_key="export DJANGO_SECRET_KEY=\"$random_string\""
echo $secret_key >> /opt/openmanage/etc/openmanage_defaults 

. /etc/default/openmanage

apt-get -y remove python-crypto
apt-get -y autoremove

find /opt/openmanage/upgrade/resources/ -name '*.deb' | xargs dpkg -i

pushd /opt/openmanage/upgrade
pip install --no-index --find-links=./resources -r requirements.txt
popd

echo "Syncing database"
pushd $OPENMANAGE_DJANGO_ROOT/omva
if [[ -z $(sudo -u postgres psql openmanage -c "select * from django_migrations where app = 'blue_mgnt' and name = '0001_initial';" -t) ]]; then
    python manage.py migrate --fake openmanage 0001_initial --noinput
    python manage.py migrate --fake blue_mgnt 0001_initial --noinput
    python manage.py migrate --fake-initial --noinput
fi
python manage.py migrate --noinput
popd

echo "Updating database..."
/opt/openmanage/upgrade/apply_sql.sh

echo "Running additional update scripts..."
sudo bash -c "PYTHONPATH=/opt/openmanage python /opt/openmanage/upgrade/apply_scripts.py"

# Restart services
for SERVICE in openmanage admin_console; do
    sv up $SERVICE
done

sudo service nginx restart

# Set VM version
python /opt/openmanage/bin/set_version.py $VERSION

echo "Upgrade complete!"
