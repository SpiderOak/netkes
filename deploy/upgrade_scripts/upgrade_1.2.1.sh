#!/bin/sh
sudo rm /opt/openmanage/netkes
sudo rm /opt/openmanage/django/omva

cd /home/openmanage
mkdir git
cd git
git clone http://github.com/SpiderOak/netkes.git --branch master

ln -s /home/openmanage/git/netkes/netkes/ /opt/openmanage/netkes
ln -s /home/openmanage/git/netkes/django/omva /opt/openmanage/django/omva

sudo echo "export DJANGO_SECRET_KEY=\"$(< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c${1:-64};echo;)\"" >> /etc/default/openmanage

# edit agent_config.json from memberUid to member
sed -i 's/memberUid/member/' /opt/openmanage/etc/agent_config.json

# rebuild sync database
(. /etc/default/openmanage && python /opt/openmanage/bin/directory_agent_main.py --rebuild-db)

sudo sv restart /etc/service/admin_console/
sudo sv restart /etc/service/openmanage/
