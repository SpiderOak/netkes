import argparse
from netkes import common
from netkes.account_mgr.accounts_api import Api

config = common.read_config_file()

parser = argparse.ArgumentParser(description='Update OMVA URL.')
parser.add_argument('url')
args = parser.parse_args()

api = Api.create(config["api_root"], config["api_user"], config["api_password"])

api.update_enterprise_settings(dict(omva_url=args.url))
