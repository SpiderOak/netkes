"""
configtest

Module containing actual test code for validating configuration.

See https://github.com/SpiderOak/netkes/issues/21

(c) 2013 SpiderOak, Inc.
"""

import ldap
import logging
import socket

# see ldap_source.py for a rant about this.
ldap.set_option(ldap.OPT_REFERRALS, 0)

REQUIRED_CONFIG_OPTIONS = set([
    'dir_uri', 'dir_base_dn', 'dir_user', 'dir_password',
    'dir_guid_source', 'dir_member_source', 'dir_username_source',
    'dir_fname_source', 'dir_lname_source',
    'auth_method',
    'api_user', 'api_password',
    'db_pass',
    'listen_addr', 'listen_port', 'groups'])


class ConfigError(Exception):
    pass

def check_configuration(config):
    """
    Check to see that our configuration file has all the configuration we need.

    Unlike the rest of the tests, failing this one will expect to
    crash the whole test as we can't expect to continue without at least having our
    config options
    """

    config_keys = set(config.keys())
    log = logging.getLogger("General Tests")
    if not config_keys >= REQUIRED_CONFIG_OPTIONS:
        log.error("==== Missing configuration options from agent_config.json ====")
        missing_keys = REQUIRED_CONFIG_OPTIONS - config_keys

        for key in missing_keys:
            log.info("Missing key: %s" % (key,))

        log.error("==== Cannot continue without the configuration options, aborting! ====")
        log.info("Please see SpiderOak documentation at:")
        log.info("https://spideroak.com/business/blue/docs/agentconf.html")
        raise ConfigError("Cannot continue.")
    else:
        log.info("==== Configuration settings check out OK! ====")

def _check_networking(uri):
    """
    Given a URI, determine generic network connectivity.
    """

    log = logging.getLogger("Network Connectivity")
    try:
        addr = socket.gethostbyname(uri)
    except socket.gaierror as e:
        log.error("DNS lookup failture for %s: %s" % (uri, e.strerror))
        log.info("Please check DNS configuration.")
        return
    else:
        log.info("DNS lookup for %s is %s. OK!" % (uri, addr,))
    
    
    
def check_ldap(config):
    """
    Validates our LDAP configuration.
    Depends on and expects that check_configuration() passes.
    """

    log = logging.getLogger("LDAP Tests")
    # Validate we can connect to the remote LDAP server.
    # Requires config['dir_uri']
    try:
        connection = ldap.initialize(config['dir_uri'])
    except ldap.LDAPError:
        log.error("==== Cannot connect to the LDAP server, unable to continue! ====")
        
        
