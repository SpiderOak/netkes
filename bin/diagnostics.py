import datetime
import json
import ldap
import subprocess
import sys
from netkes import common
from netkes.account_mgr.user_source import ldap_source
from netkes.account_mgr.accounts_api import Api
from redact_agent_config import redact
from restore_backup import get_backup
from scapy.all import traceroute

agent_config = '/opt/openmanage/etc/agent_config.json'
diagnostics_base = '/opt/openmanage/tmp_diagnostics'
diagnostics_dir = sys.argv[1]
date = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')

config = common.read_config_file()

spideroak_addr_list = ["spideroak.com", "38.121.104.4", "38.121.104.5", "38.121.104.20", "38.121.104.21"]
ubuntu_addr_list = ["archive.ubuntu.com"]


def ldap_test(user, password):
    #ldap_conn = ldap_source.OMLDAPConnection(config["dir_uri"], config["dir_base_dn"], config["dir_user"], config["dir_password"])
    auth_user = ldap_source.get_auth_username(config, '{}'.format(user))
    conn = ldap.initialize(config['dir_uri'])
    print conn.simple_bind_s(auth_user, '{}'.format(password))


def validate_json(filename):
    try:
        with open(filename) as f:
            json.load(f)
            print "agent_config.json is valid!"
            check_settings()
    except ValueError as e:
        print "agent_config.json not valid: '{}'".format(e)
        return None


def check_settings():
    print_message("CHECKING REQUIRED SETTINGS")
    required_settings = ["api_password", "api_root", "api_user", "billing_root", "db_pass", "enable_local_users",
                         "listen_addr", "listen_port", "local_password", "send_activation_email"]
    ldap_settings = ["dir_base_dn", "dir_fname_source", "dir_guid_source", "dir_lname_source", "dir_member_source",
                     "dir_password", "dir_type", "dir_uri", "dir_user", "dir_username_source"]

    if config["auth_method"] == "ldap":
        required_settings = required_settings + ldap_settings
    elif config["auth_method"] == "local":
        pass
    else:
        print "auth_method is empty or invalid, check agent_config.json"

    for setting in required_settings:
        if not str(config[setting]):
            print setting + " is empty, check agent_config.json."
        else:
            print setting + " contains data."


def check_service(service):
    status = subprocess.Popen(["sv", "status", service], stdout=subprocess.PIPE)
    out, err = status.communicate()

    if out[:3] == "run":
        print service + " is running!:"
        print out
    elif out[:4] == "down":
        print service + " is down!:"
        print out
    else:
        print service + " status unknown, check service:"
        print status


def print_message(text):
    print ''
    print "##### " + text + " #####"
    print ''


if __name__ == '__main__':

    # Validate agent_config.json
    print_message("VALIDATING AGENT_CONFIG.JSON")
    print validate_json(agent_config)

    # Traceroute to SpiderOak backend.
    print_message("RUNNING TRACEROUTE TO SPIDEROAK BACKEND")
    for address in spideroak_addr_list:
        traceroute(address)

    # Traceroute to Ubuntu repos.
    print_message("RUNNING TRACEROUTE TO UBUNTU REPOSITORIES")
    for address in ubuntu_addr_list:
        traceroute(address)

    api = Api.create(
        config["api_root"],
        config["api_user"],
        config["api_password"],
    )

    # Ping the accounts_api.

    print_message("PINGING ACCOUNTS API")
    print api.ping()

    # Verify that a setting can be changed via the accounts_api.
    # This might be better/safer if we created a 'dummy' setting for the purpose of testing.
    print_message("TESTING EDIT SETTINGS")

    current_autopurge = api.enterprise_settings()['autopurge_interval']
    print "Currently, deleted items are set to purge every '{}' days.".format(current_autopurge)
    api.update_enterprise_settings(dict(autopurge_interval=current_autopurge+1))

    temp_autopurge = api.enterprise_settings()['autopurge_interval']
    print "Deleted items are now set to purge every '{}' days.".format(temp_autopurge)

    api.update_enterprise_settings(dict(autopurge_interval=current_autopurge))
    current_autopurge = api.enterprise_settings()['autopurge_interval']
    print "The deleted items purge has been returned to '{}' days.".format(current_autopurge)

    # Test connection to AD/LDAP
    # Better testing needed.

    print_message("TESTING AD/LDAP CONNECTION")

    if len(sys.argv) != 4:
        print "Incorrect number of arguments or AD/LDAP not configured. Skipping AD/LDAP auth test."
    else:
        ldap_test(sys.argv[2], sys.argv[3])

    print_message("DOWNLOADING BACKUP")

    backup_filename = 'openmanage-backup-{}.tar.bz2'.format(date)
    backup_path = '{}/{}'.format(diagnostics_base, backup_filename)

    get_backup(backup_path)

    # Add backup verification

    print_message("CHECKING STATUS OF SERVICES")

    check_service("openmanage")
    check_service("admin_console")

    print_message("PROVIDING REDACTED COPY OF AGENT_CONFIG.JSON")

    redact('{}/{}/redacted_agent_config.json'.format(diagnostics_base, diagnostics_dir))