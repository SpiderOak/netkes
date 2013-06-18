'''
api_interface.py

(c) 2011 SpiderOak, Inc.

Provides an interface to the billing and new user APIs.

'''

import json
import logging
import re
from urllib import quote
import urllib2

from common import get_config
from Pandora import https

API_URL_BASE = "%s/%s"
NO_PLANS = "No storage plans provided."

class ApiActionFailedError(Exception):
    pass

class ManipulateUserFailed(ApiActionFailedError):
    pass

class FetchInformationFailed(ApiActionFailedError):
    pass


_AVATAR_ID_URL = "users/%d"
_EMAIL_URL = "users/byemail/%s"
def _make_api_url_for_user(user):
    """
    Creates a string to reference the user in the SpiderOak Billing API.
    Currently supports using either an avatar_id or email address.
    """
    if 'avatar_id' in user:
        return _AVATAR_ID_URL % (user['avatar_id'],)
    else:
        return _EMAIL_URL % (quote(user['email']),)
    
def _run_api_call(action, data=None):
    ''' 
    Runs a call against the SpiderOak API.
    Returns a python object containing the response.
    '''
    log = logging.getLogger('run_api_call')
    uri = API_URL_BASE % (get_config()['api_root'], action, )

    https_handler = https.VerifiedHTTPSHandler()
    https_opener = urllib2.build_opener(https_handler)
    urllib2.install_opener(https_opener)

    auth_mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
    auth_mgr.add_password(realm=None, uri=uri,
                          user=get_config()['api_user'],
                          passwd=get_config()['api_password'])

    log.debug("Trying with user %s and pass %s" % (get_config()['api_user'],
                                                   get_config()['api_password'],))

    auth_handler = urllib2.HTTPBasicAuthHandler(auth_mgr)
    auth_opener = urllib2.build_opener(auth_handler)
    urllib2.install_opener(auth_opener)

    if data is None:
        fh = urllib2.urlopen(uri)
    else:
        datastr = json.dumps(data)
        fh = urllib2.urlopen(uri, datastr)

    json_string = fh.read()
    retr_data = json.loads(json_string)

    return retr_data


def create_user(user, promo_code=None):
    '''
    Uses the SpiderOak new user API to create a new user. 
    Returns: newly created user data information..
    Raises ManipulateUserFailed on failure.
    '''
    
    new_user_data = {"action": "create_user",
                     "auto_username_seq": True,
                     "firstname": user['firstname'],
                     "lastname": user['lastname'],
                     "email": user['email'],
                     "group_id": user['group_id'],
                     }
    if promo_code is not None:
        new_user_data["promo"] = promo_code

    try:
        result = _run_api_call("users/", new_user_data)
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise ManipulateUserFailed(str(e))
    
    if result['success']:
        return result                
    else:
        raise ManipulateUserFailed("%s: result['reason']" % user['email'])


def set_user_group(user, promo_code=None):
    '''
    Sets the group_id of a specified avatar.
    Raises ManipulateUserFailed in error.
    '''
    user_group_data = {"action" : "set_group",
                      "group_id": user['group_id'],
                      }
    if promo_code is not None:
        user_group_data['promo_code'] = promo_code

    try:
        result = _run_api_call(_make_api_url_for_user(user),
                               user_group_data)
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise ManipulateUserFailed(str(e))

    if result['success']:
        return result
    else:
        raise ManipulateUserFailed(result['reason'])
    

def activate_user(user):
    '''
    Activates the given avatar.
    Raises ManipulateUserFailed in error.
    '''
    activate_data = {"action" : "set_enabled",
                     "enabled": True,
                     }
    try:
        result = _run_api_call(_make_api_url_for_user(user),
                               activate_data)
    except Exception as e:
        raise ManipulateUserFailed(str(e))

    if result['success']:
        return result
    else:
        raise ManipulateUserFailed(result['reason'])


def deactivate_user(user):
    '''
    Deactivates the given avatar.
    Raises ManipulateUserFailed in error.
    '''
    deactivate_data = {"action" : "set_enabled",
                       "enabled": False,
                       }
    try:
        result = _run_api_call(_make_api_url_for_user(user),
                               deactivate_data)
    except Exception as e:
        raise ManipulateUserFailed(str(e))

    if result['success']:
        return result
    else:
        raise ManipulateUserFailed(result['reason'])


def purge_user(user):
    '''
    Deactivates the given avatar.
    Raises ManipulateUserFailed in error.
    '''
    purge_data = {"action" : "purge_account", }
    try:
        result = _run_api_call(_make_api_url_for_user(user),
                               purge_data)
    except Exception as e:
        raise ManipulateUserFailed(str(e))

    if result['success']:
        return result
    else:
        raise ManipulateUserFailed(result['reason'])


def change_email(user):
    '''
    Sets the email on the given avatar_id to the email.
    Raises ManipulateUserFailed in error.
    '''
    change_data = {"action" : "set_email",
                   "email"  : user['email'],
                   }
    try:
        # This accounts for the fact that we might pass in two email
        # addresses when looking up the user by email.
        if 'old_email' in user:
            api_url = _make_api_url_for_user({'email': user['old_email']})
        else:
            api_url = _make_api_url_for_user(user)
        result = _run_api_call(api_url, change_data)
    except Exception as e:
        raise ManipulateUserFailed(str(e))
    
    if result['success']:
        return result
    else:
        raise ManipulateUserFailed(result['reason'])


def fetch_users():
    '''
    Returns a list of the users currently registered with SpiderOak.
    Raises FetchInformationError on problem.
    '''
    try:
        result = _run_api_call("users/")
    except Exception as e:
        raise FetchInformationFailed(str(e))

    return result


def fetch_plans(promo_code=None):
    '''
    Returns a list of the plans available to us.
    Raises FetchInformationError on problem.
    '''
    if promo_code is None:
        action = "plans/"
    else:
        action = "plans/?promo=%s" % promo_code
        
    try:
        result = _run_api_call(action)
    except Exception as e:
        raise FetchInformationFailed(str(e))

    if len(result) < 1:
        raise FetchInformationFailed(NO_PLANS)

    return result

