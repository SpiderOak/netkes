from netkes.netkes_agent import config_mgr

config = config_mgr.ConfigManager(config_mgr.default_config())

config.config['user_sources'] = []

USER_SOURCE_NAME = 'default_ldap'

if 'user_source' not in config.config:
    user_source = {
        'dir_name': USER_SOURCE_NAME,
    }

    for key in list(config.config.iterkeys()):
        if key.startswith('dir_'):
            user_source[key] = config.config[key]
            del config.config[key]

    user_source['dir_ldap_type'] = user_source['dir_type']
    user_source['dir_type'] = 'ldap'

    config.config['user_sources'].append(user_source)

    for group in config.config['groups']:
        group['user_source'] = USER_SOURCE_NAME

    config.apply_config()
