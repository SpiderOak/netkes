#!/bin/bash

if [ -e ~/.ran_firstsetup ]; then
    exit 0
fi

. /etc/default/openmanage

# Setup the NetKES escrow keys.
if [ ! -f /var/lib/openmanage/keys/base.cfg ]; then
$OPENMANAGE_ROOT/bin/make_keys.sh $OPENMANAGE_BRAND
fi

# Setup django
pushd $OPENMANAGE_DJANGO_ROOT/omva
python manage.py syncdb --noinput
python manage.py createsuperuser --noinput --username="console_admin" --email="invalid@email.act"
popd

$OPENMANAGE_ROOT/netkes/upgrade/apply_sql.sh
python $OPENMANAGE_ROOT/netkes/upgrade/apply_scripts.py

if [ -e $OPENMANAGE_ROOT/netkes/account_mgr/user_source ]; then
    sudo ln -s $OPENMANAGE_ROOT/bin/run_openmanage.sh /etc/cron.hourly/run_openmanage || exit 1
fi

sudo mkdir -p /etc/service/openmanage/supervise
sudo ln -s $OPENMANAGE_ROOT/etc/service/openmanage/run /etc/service/openmanage/run
sudo sv start openmanage


touch ~/.ran_firstsetup



