#!/bin/sh

bash -c ". /etc/default/openmanage; PYTHONPATH=/opt/openmanage/django:$PYTHONPATH python permissions.py"

(. /etc/default/openmanage && python manage.py syncdb --noinput)

sudo apt-get remove -y python-django

sudo pip install --upgrade $HOME/netkes/upgrade/resources/pip-1.4.1.tar.gz
sudo pip install $HOME/netkes/upgrade/resources/Django-1.5.5.tar.gz
sudo pip install $HOME/netkes/upgrade/resources/greenlet-0.4.1.zip
sudo pip install $HOME/netkes/upgrade/resources/eventlet-0.14.0.tar.gz
