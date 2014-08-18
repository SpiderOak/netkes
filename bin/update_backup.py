#!/usr/bin/env python

import os
import datetime
from hashlib import sha256
import subprocess
from binascii import b2a_base64

os.environ['DJANGO_SETTINGS_MODULE'] = 'omva.settings'

from openmanage.views import create_secret_box
from netkes import common
from netkes.account_mgr.accounts_api import Api

config = common.read_config_file()

api = Api.create(
    config["api_root"],
    config["api_user"],
    config["api_password"],
)

secret_box, nonce = create_secret_box(config['api_password'], config['api_user'])

date = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
filename = 'openmanage-backup-%s.tar.bz2' % date
path = '/opt/openmanage/tmp_backup/%s' % filename

subprocess.call(['/opt/openmanage/bin/create_backup.sh', date])

with open(path) as f:
    data = secret_box.encrypt(f.read(), nonce)
data = b2a_base64(data)

backup = {
    'sha256': sha256(data).hexdigest(),
    'data': data,
}

api.update_backup(backup)
