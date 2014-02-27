from netkes.netkes_agent import config_mgr

config = config_mgr.ConfigManager(config_mgr.default_config())

for group in config.config['groups']:
    if 'user_source' not in group:
        group['user_source'] = 'ldap'
    if 'admin_group' not in group:
        group['admin_group'] = False
    if 'priority' not in group:
        group['priority'] = 0

config.apply_config()

