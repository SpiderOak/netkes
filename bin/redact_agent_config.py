#!/usr/bin/env python

import json

AGENT_CONFIG = '/opt/openmanage/etc/agent_config.json'
REDACTED_AGENT_CONFIG = '/home/openmanage/redacted_agent_config.json'
TO_REDACT = ['dir_password', 'api_password', 'local_password']

if __name__ == '__main__':
    with open(AGENT_CONFIG) as cf:
        config = json.load(cf)

    for item in TO_REDACT:
        if item in config:
            config[item] = 'fake_' + item

    with open(REDACTED_AGENT_CONFIG, 'w') as cf:
        json.dump(config, cf, sort_keys=True, indent=4)

    print "agent_config.json successfully redacted."
    print "File written to /home/openmanage/redacted_agent_config.json"

