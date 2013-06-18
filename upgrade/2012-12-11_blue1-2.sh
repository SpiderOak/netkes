cd /opt/openmanage
rm -rf netkes
git clone https://spideroak.com/dist/net_kes.git
ln -s /opt/openmanage/net_kes/netkes/ /opt/openmanage/netkes

rm -rf django/omva
ln -s /opt/openmanage/net_kes/django/omva /opt/openmanage/django/omva

cd django/apps/blue_management
sudo git pull

cd ../so_common/
sudo git pull

sudo -u postgres psql -d openmanage -a -f /opt/openmanage/net_kes/sql/2012-12-11_blue_1_2.sql

sudo sv restart /etc/service/admin_console/
sudo sv restart /etc/service/openmanage/

