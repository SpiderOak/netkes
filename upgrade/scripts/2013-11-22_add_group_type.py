from netkes.netkes_agent import config_mgr

config = config_mgr.ConfigManager(config_mgr.default_config())

for group in config.config['groups']:
    if 'user_source' not in group:
        group['user_source'] = 'ldap'

config.apply_config()
