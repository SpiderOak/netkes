restart:
	sudo sv restart admin_console

apply_sql:
	/opt/openmanage/upgrade/apply_sql.sh

apply_scripts:
	sudo bash -c "PYTHONPATH=/opt/openmanage python /opt/openmanage/upgrade/apply_scripts.py"

manage: 
	cd ~/netkes/django/omva; \
	. /etc/default/openmanage; python manage.py ${COMMAND}

test_netkes:
	python -m netkes/account_mgr/test/test_account_mgr 
	python -m netkes/account_mgr/test/test_accounts_api
	python -m netkes/account_mgr/test/test_ldap_reader

test: COMMAND = test blue_mgnt.tests.TestViewAuth
test: manage
test: test_netkes

psql:
	sudo -u postgres psql openmanage

build_release: VERSION = ${VERSION}
build_release:
ifndef VERSION
	$(error Need VERSION argument)
endif
	sudo rm -rf /tmp/management_console_${VERSION} && \
	mkdir /tmp/management_console_${VERSION} && \
	cd /tmp/management_console_${VERSION} && \
	git clone https://github.com/SpiderOak/netkes.git --branch=management_console_${VERSION} && \
	cd netkes/deploy && \
	sudo ./make_tarball.sh .. ${VERSION} ~/storage_vm_builder/extrafiles/management && \
	rm -rf ~/openmanage-${VERSION}.tar.bz2 && \
	cp openmanage-${VERSION}.tar.bz2 ~/ && \
	sudo rm -rf /tmp/management_console_${VERSION}

setup_dev:
	sudo mv /opt/openmanage/netkes /opt/openmanage/netkes.orig && \
	sudo ln -s /home/openmanage/netkes/netkes/ /opt/openmanage/netkes && \
	sudo mv /opt/openmanage/django/omva /opt/openmanage/django/omva.orig && \
	sudo ln -s /home/openmanage/netkes/django/omva/ /opt/openmanage/django/omva && \
	sudo mv /opt/openmanage/django/apps /opt/openmanage/django/apps.orig && \
	sudo ln -s /home/openmanage/netkes/django/apps/ /opt/openmanage/django/apps && \
	sudo mv /opt/openmanage/upgrade/ /opt/openmanage/upgrade.orig && \
	sudo ln -s /home/openmanage/netkes/upgrade/ /opt/openmanage/upgrade && \
	sudo mv /opt/openmanage/bin/ /opt/openmanage/bin.orig && \
	sudo ln -s /home/openmanage/netkes/bin/ /opt/openmanage/bin && \
	sudo mv /opt/openmanage/sql/ /opt/openmanage/sql.orig && \
	sudo ln -s /home/openmanage/netkes/sql/ /opt/openmanage/sql && \
	sudo mv /opt/openmanage/etc/service/ /opt/openmanage/etc/service.orig && \
	sudo ln -s /home/openmanage/netkes/etc/service/ /opt/openmanage/etc/service && \
	cp -r /opt/openmanage/django/apps.orig/blue_management/blue_mgnt/static/fonts/ /opt/openmanage/django/apps/blue_management/blue_mgnt/static/fonts/

mc_css:
	lessc -x ~/netkes/django/apps/blue_management/blue_mgnt/static/less/style.less > ~/netkes/django/apps/blue_management/blue_mgnt/static/css/console-min.css
