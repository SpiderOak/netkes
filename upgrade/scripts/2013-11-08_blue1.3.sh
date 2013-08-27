#!/bin/sh

bash -c ". /etc/default/openmanage; PYTHONPATH=/opt/openmanage/django:$PYTHONPATH python /opt/openmanage/permissions.py"

(. /etc/default/openmanage && python manage.py syncdb --noinput)

sudo apt-get remove -y python-django

sudo pip install --upgrade /opt/openmanage/upgrade/resources/pip-1.4.1.tar.gz
sudo pip install /opt/openmanage/upgrade/resources/Django-1.5.5.tar.gz
