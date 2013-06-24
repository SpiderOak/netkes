"""
cmdline_utils.py

Helper functions and classes for OpenManage command-line utilities.
"""
import csv
import json
import logging

import account_mgr
from account_mgr.local_source import set_user_password, set_multi_passwords


SETPW_REQUIRED_KEYS = frozenset(['email_addr', 'password'])
CREATE_REQUIRED_KEYS = frozenset(['email_addr', 'given_name', 'surname', 'group_id'])
SET_EMAIL_REQUIRED_KEYS = frozenset(['email_addr', 'new_email'])
SET_GROUP_REQUIRED_KEYS = frozenset(['email_addr', 'group_id'])

class UsersActionError(Exception):
    pass

class CSVMissingKeys(Exception):
    pass

def assure_keys(dict_reader, required_keys):
    """
    Reads from a csv.DictReader object and creates a list.  Ensures
    that required_keys are in every row from the DictReader.

    :param dict_reader: The opened csv.DictReader object.
    :param required_keys: Set of keys required in every row in the CSV file.
    :returns list: list of change dicts.
    """
    rows = list()
    for row in dict_reader:
        keys = set(row.keys())
        if required_keys <= keys:
            rows.append(row)
        else:
            raise CSVMissingKeys("Missing one or more of required keys: %s" %
                                 (required_keys, ))        
    return rows
        
def run_csv_file(db_conn, filename, optdict):
    """Runs the appropriate actions from a CSV file.

    :param db_conn: DB connection object
    :param filename: CSV filename
    :param optdict: Options dictionary.
    :returns int: number of successful user actions.
    """

    api = account_mgr.get_api(config)
    log = logging.getLogger("run_csv_file")
    dict_reader = csv.DictReader(filename)
    
    if 'setpw' in optdict:
        user_dicts = assure_keys(dict_reader, SETPW_REQUIRED_KEYS)
        emails = (email for email in user_dicts['email_addr'])
        pws = (pw for pw in user_dicts['password'])
        set_multi_passwords(db_conn, emails, pws)

        # All done, so leave the function here.
        return len(user_dicts)

    success_count = 0
    if 'create' in optdict:
        # Runs the creation routine for each user.
        user_dicts = assure_keys(dict_reader, CREATE_REQUIRED_KEYS)
        for user in user_dicts:
            api.create_user(
                {'name': user['given_name'] + ' ' + user['surname'],
                 'email': user['email_addr'],
                 'group_id': user['group_id'],
                })
            success_count += 1

    elif 'set_email' in optdict:
        # Sets emails for each user.
        user_dicts = assure_keys(dict_reader, SET_EMAIL_REQUIRED_KEYS)
        for user in user_dicts:
            api.edit_user(user['email_addr'], dict(email=user['new_email']))
            success_count += 1
    elif 'set_group' in optdict:
        # Sets groups for each user.
        user_dicts = assure_keys(dict_reader, SET_GROUP_REQUIRED_KEYS)
        for user in user_dicts:
            api.edit_user(user['email_addr'], dict(group_id=user['group_id']))
            success_count += 1
    elif 'disable' in optdict:
        user_dicts = assure_keys(dict_reader, frozenset(['email_addr']))
        for user in user_dicts:
            api.edit_user(user['email_addr'], dict(enabled=False))
            success_count += 1
    elif 'enable' in optdict:
        user_dicts = assure_keys(dict_reader, frozenset(['email_addr']))
        for user in user_dicts:
            api.edit_user(user['email_addr'], dict(enabled=True))
            success_count += 1
    else:
        raise UsersActionError("Got an action that's not accounted for!")
        
    return success_count

def run_single_command(db_conn, email_address, optdict):
    log = logging.getLogger("run_single_command")
    api = account_mgr.get_api(config)

    if optdict['setpw']:
        set_user_password(db_conn, email_address, optdict['password'])

    elif optdict['create']:
        api.create_user(
            {'name': optdict['given_name'] + ' ' + optdict['surname'],
             'email': optdict['email_addr'],
             'group_id': optdict['group_id'],
            })
    elif optdict['set_email']:
        api.edit_user(optdict['email_addr'], dict(email=optdict['new-email']))
    elif optdict['set_group']:
        api.edit_user(optdict['email_addr'], dict(group_id=optdict['group_id']))
    elif optdict['disable']:
        api.edit_user(optdict['email_addr'], dict(enabled=False))
    elif optdict['enable']:
        api.edit_user(optdict['email_addr'], dict(enabled=True))
    else:
        raise UsersActionError("Got an action that's not accounted for!")

def get_user_list():
    """Fetches the list of users from SpiderOak, returns it as JSON."""
    api = account_mgr.get_api(config)
    return api.list_users()

def csvify_userlist(csvfile, users):
    """Takes a JSON-ified list of users, and returns it as a CSV file."""
    user_list = json.loads(users)
    dict_writer = csv.DictWriter(csvfile,
                                 ['email', 'firstname', 'lastname',
                                  'group_id', 'share_id', 'bytes_stored',
                                  'enabled',],
                                 extrasaction='ignore')
    dict_writer.writeheader()
    dict_writer.writerows(user_list)

    return None
        

def run_command(db_conn, optdict):
    """Matches the options in optdict to a specific action we need to do.

    :param optdict: options dictionary

    """

    if 'csv_file' in optdict:
        run_csv_file(db_conn, optdict.pop('csv_file'), optdict)
    elif 'email_addr' in optdict:
        run_single_command(db_conn, optdict.pop('email_addr'), optdict)
    elif 'users_csv' in optdict or 'users_json' in optdict:
        users = get_user_list()
        if 'users_csv' in optdict:
            return csvify_userlist(optdict['users_csv'], users)

        return users

