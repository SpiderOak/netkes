import bcrypt
from hashlib import sha256
from base64 import b64encode
from netkes.netkes_agent import config_mgr
from netkes.account_mgr.accounts_api import Api

config = config_mgr.ConfigManager(config_mgr.default_config())

# This only needs to be run for existing vms. 
# It's unnecessary for new vms. 
if config.config['api_password']:
    hash_ = sha256(config.config['api_password']).digest()
    salt = '$2a$14$' + b64encode(hash_[:16]).rstrip('=')
    new_pass = bcrypt.hashpw(config.config['api_password'], salt)
    api_pass = new_pass[len(salt):]

    api = Api.create(
        config.config["api_root"],
        config.config["api_user"],
        config.config["api_password"],
    )

    config.config['local_password'] = new_pass
    config.config['api_password'] = api_pass
    api.update_enterprise_password(api_pass)

    config.apply_config()

