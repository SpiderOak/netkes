from netkes.netkes_agent import config_mgr

config = config_mgr.ConfigManager(config_mgr.default_config())

if 'send_activation_email' not in config.config:
    config.config['send_activation_email'] = True

config.apply_config()
