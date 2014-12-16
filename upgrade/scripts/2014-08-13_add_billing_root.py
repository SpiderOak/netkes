from netkes.netkes_agent import config_mgr

config = config_mgr.ConfigManager(config_mgr.default_config())

if 'billing_root' not in config.config:
    config.config['billing_root'] = 'https://spideroak.com/apis/billing/v1/'

config.apply_config()
