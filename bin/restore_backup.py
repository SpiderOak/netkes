#!/usr/bin/env python

import os
import datetime
import subprocess
from binascii import a2b_base64
from nacl.exceptions import CryptoError

from netkes import common
from netkes.account_mgr.accounts_api import Api

os.environ['DJANGO_SETTINGS_MODULE'] = 'omva.settings'

from openmanage.views import create_secret_box

config = common.read_config_file()

api = Api.create(
    config["api_root"],
    config["api_user"],
    config["api_password"],
)


def get_backup(filepath):
    backup = api.backup()
    data = a2b_base64(backup['data'])

    try:
        secret_box, nonce = create_secret_box(config['local_password'], config['api_user'])
        data = secret_box.decrypt(data)
    except CryptoError:
        # Fall back to api_password in case any old accounts still use it
        secret_box, nonce = create_secret_box(config['api_password'], config['api_user'])
        data = secret_box.decrypt(data)

    with open(filepath, 'w') as f:
        f.write(data)

if __name__ == '__main__':

    date = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    filename = 'openmanage-backup-%s.tar.bz2' % date
    path = '/opt/openmanage/tmp_backup/%s' % filename

    get_backup(path)
    subprocess.call(['/opt/openmanage/bin/restore_omva.sh', path])
