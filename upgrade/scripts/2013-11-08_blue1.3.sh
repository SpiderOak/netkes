#!/bin/sh

. /etc/default/openmanage
PYTHONPATH=/opt/openmanage/django:$PYTHONPATH 
python /opt/openmanage/django/apps/blue_management/blue_mgnt/permissions.py

python /opt/openmanage/django/omva/manage.py syncdb --noinput

sudo apt-get remove -y python-django

sudo pip install --upgrade /opt/openmanage/upgrade/resources/pip-1.4.1.tar.gz
sudo pip install /opt/openmanage/upgrade/resources/Django-1.5.5.tar.gz
