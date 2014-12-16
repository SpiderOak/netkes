import sys
from netkes import common
from netkes.account_mgr.accounts_api import Api

config = common.read_config_file()

if len(sys.argv) != 2:
    print "version is required"
    print "python set_version.py 1.2.3"
    sys.exit(0)

if config['api_password']:
    api = Api.create(
        config["api_root"],
        config["api_user"],
        config["api_password"],
    )
    api.update_enterprise_settings(dict(api_version=sys.argv[1]))
