import glob
from subprocess import call

from netkes import common
from netkes.account_mgr import get_cursor

def apply_scripts():
    config = common.read_config_file()
    files = glob.glob('/opt/openmanage/upgrade/scripts/*.sh') 
    files = sorted(files)

    for file_ in files:
        with get_cursor(config) as cur:
            cur.execute('select * from updates where name=%s', (file_, ))
            if cur.rowcount == 0:
                print "Applying", file_
                retcode = call([file_], shell=True)
                if retcode == 0:
		    cur.execute('insert into updates (name) values (%s)', (file_, ))

if __name__ == '__main__':
    apply_scripts()
