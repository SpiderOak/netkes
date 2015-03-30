restart:
	sudo sv restart admin_console

apply_sql:
	/opt/openmanage/upgrade/apply_sql.sh

apply_scripts:
	sudo bash -c "PYTHONPATH=/opt/openmanage python /opt/openmanage/upgrade/apply_scripts.py"

manage: 
	cd ~/netkes/django/omva; \
	. /etc/default/openmanage; python manage.py ${COMMAND}

psql:
	sudo -u postgres psql openmanage
