#!/usr/bin/env python

import os
import datetime
from hashlib import sha256
import subprocess
from binascii import a2b_base64
import bcrypt
import nacl.secret

from netkes import common
from netkes.account_mgr.accounts_api import Api

config = common.read_config_file()

api = Api.create(
    config["api_root"],
    config["api_user"],
    config["api_password"],
)

def create_secret_box(password, username):
    key = bcrypt.kdf(
        password.encode('utf-8'),
        username,                
        nacl.secret.SecretBox.KEY_SIZE, 
        100,
    )
    
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    return nacl.secret.SecretBox(key), nonce

secret_box, nonce = create_secret_box(config['api_password'], config['api_user'])

date = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
filename = 'openmanage-backup-%s.tar.bz2' % date
path = '/opt/openmanage/tmp_backup/%s' % filename

backup = api.backup()

data = a2b_base64(backup['data'])
data = secret_box.decrypt(data)

with open(path, 'w') as f:
    f.write(data)

subprocess.call(['/opt/openmanage/bin/restore_omva.sh', path])
