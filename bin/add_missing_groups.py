#!/usr/bin/python

from netkes.netkes_agent import config_mgr
from netkes.account_mgr.accounts_api import Api

config = config_mgr.ConfigManager(config_mgr.default_config())

api = Api.create(
    config.config['api_root'],
    config.config['api_user'],
    config.config['api_password'],
)


groups = api.list_groups()


def find_group(group_id):
    for g in config.config['groups']:
        if g['group_id'] == group_id:
            return g


for group in groups:
    if not find_group(group['group_id']):
        config.config['groups'].append({
            'admin_group': False,
            'group_id': group['group_id'],
            'ldap_id': '',
            'priority': 0,
            'type': 'dn',
            'user_source': 'local',
        })


config.apply_config()
