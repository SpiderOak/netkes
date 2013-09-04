import json
import urllib
import urllib2
import types
import logging

from api_client import ApiClient


class Error(Exception):
    pass


class ApiMeta(type):
    def __new__(cls, name, bases, attrs):
        for attr_name, attr_value in attrs.iteritems():
            if isinstance(attr_value, types.FunctionType):
                attrs[attr_name] = cls.log_exceptions(attr_value)

        return super(ApiMeta, cls).__new__(cls, name, bases, attrs)

    @classmethod
    def log_exceptions(cls, func):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Error:
                log = logging.getLogger('accounts_api')
                log.error('%s - %s - %s' % (func.__name__, args, kwargs))
                raise
        return wrapper
        

class Api(object):
    __metaclass__ = ApiMeta

    class BadParams(Error):
        pass
    class NotFound(Error):
        pass
    class DuplicateGroupName(Error):
        pass
    class DuplicateUsername(Error):
        pass
    class DuplicateEmail(Error):
        pass
    class BadPlan(Error):
        pass
    class BadGroup(Error):
        pass
    class QuotaExceeded(Error):
        pass
    class EmailNotSent(Error):
        pass

    @classmethod
    def create(cls, base, username, password):
        """Factory method using default ApiClient class."""
        client = ApiClient(base, username, password)
        return cls(client)

    def __init__(self, client):
        self.Error = Error
        self.client = client

    def ping(self):
        return self.client.get_json('ping')

    ### Plans

    def list_plans(self):
        return self.client.get_json('plans')

    ### Quota

    def quota(self):
        return self.client.get_json('partner/quota')

    ### Features

    def enterprise_features(self):
        return self.client.get_json('partner/features')

    ### Settings

    def enterprise_settings(self):
        return self.client.get_json('partner/settings')

    def update_enterprise_settings(self, settings):
        try:
            return self.client.post_json('partner/settings', settings)
        except urllib2.HTTPError, err:
            if err.code == 400:
                raise self.BadParams()
            raise

    def update_enterprise_password(self, new_password):
        try:
            return self.client.post_json('partner/password', new_password)
        except urllib2.HTTPError, err:
            if err.code == 400:
                raise self.BadParams()
            raise

    ### Groups

    def list_groups(self):
        return self.client.get_json('groups/')

    def search_groups(self, name):
        return self.client.get_json('groups/?search=%s' % urllib.quote(name))

    def create_group(self, group_info):
        try:
            resp = self.client.post_json_raw_response(
                'groups/', group_info)
        except urllib2.HTTPError, err:
            if err.code == 400:
                raise self.BadParams()
            elif err.code == 409:
                data = json.loads(err.read())
                if 'name' in data['conflicts']:
                    raise self.DuplicateGroupName()
                elif 'plan_id' in data['conflicts']:
                    raise self.BadPlan()
            raise
        return int(resp.info()['location'].rsplit('/', 1)[-1])

    def get_group(self, group_id):
        try:
            return self.client.get_json('groups/%d' % (group_id,))
        except urllib2.HTTPError, err:
            if err.code == 404:
                raise self.NotFound()
            raise

    def edit_group(self, group_id, group_info):
        try:
            self.client.post_json('groups/%d' % (group_id,), group_info)
        except urllib2.HTTPError, err:
            if err.code == 404:
                raise self.NotFound()
            elif err.code == 400:
                raise self.BadParams()
            elif err.code == 409:
                data = json.loads(err.read())
                if 'name' in data['conflicts']:
                    raise self.DuplicateGroupName()
                elif 'plan_id' in data['conflicts']:
                    raise self.BadPlan()
                elif 'avatars_over_quota' in data['conflicts']:
                    raise self.QuotaExceeded()
            raise

    def delete_group(self, group_id, new_group_id=None):
        try:
            if new_group_id:
                self.client.delete('groups/%d?move_to=%d' % (group_id, new_group_id))
            else:
                self.client.delete('groups/%d' % (group_id,))
        except urllib2.HTTPError, err:
            if err.code == 404:
                raise self.NotFound()
            raise

    ### Shares

    def _create_query_string(self, limit, offset):
        get_params = dict()
        if limit:
            get_params['limit'] = limit
        if offset:
            get_params['offset'] = offset
        query_string = ''
        if get_params:
            query_string = '?%s' % urllib.urlencode(get_params)
        return query_string

    def list_shares_for_brand(self, limit=None, offset=None):
        query_string = self._create_query_string(limit, offset)
        return self.client.get_json('shares/%s' % query_string)

    ### Users

    def list_users(self, limit=None, offset=None):
        query_string = self._create_query_string(limit, offset)
        return self.client.get_json('users/%s' % query_string)

    def search_users(self, name_or_email, limit=None, offset=None):
        query_string = self._create_query_string(limit, offset)
        if query_string:
            query_string = '&' + query_string
        return self.client.get_json('users/?search=%s%s' % (urllib.quote(name_or_email), query_string))
    def get_user_count(self):
        return self.client.get_json('users/?action=user_count')['user_count']

    def create_user(self, user_info):
        try:
            return self.client.post_json('users/', user_info)
        except urllib2.HTTPError, err:
            if err.code == 400:
                raise self.BadParams()
            elif err.code == 409:
                data = json.loads(err.read())
                if 'username' in data['conflicts']:
                    raise self.DuplicateUsername()
                if 'email' in data['conflicts']:
                    raise self.DuplicateEmail()
                elif 'plan_id' in data['conflicts']:
                    print 'data', data
                    raise self.BadPlan()
                elif 'group_id' in data['conflicts']:
                    raise self.BadGroup()
            raise

    def get_user(self, username_or_email):
        try:
            return self.client.get_json(
                'users/%s' % (username_or_email,))
        except urllib2.HTTPError, err:
            if err.code == 404:
                raise self.NotFound()
            raise

    def list_devices(self, username_or_email):
        try:
            return self.client.get_json(
                'users/%s/devices' % (username_or_email,))
        except urllib2.HTTPError, err:
            if err.code == 404:
                raise self.NotFound()
            raise

    def list_shares(self, username_or_email):
        try:
            return self.client.get_json(
                'users/%s/shares/' % (username_or_email,))
        except urllib2.HTTPError, err:
            if err.code == 404:
                raise self.NotFound()
            raise

    def get_share(self, username_or_email, room_key):
        try:
            return self.client.get_json(
                'users/%s/shares/%s' % (username_or_email, room_key))
        except urllib2.HTTPError, err:
            if err.code == 404:
                raise self.NotFound()
            raise

    def edit_share(self, username_or_email, room_key, enable):
        action = 'enable' if enable else 'disable'
        try:
            return self.client.post_json(
                'users/%s/shares/%s?action=%s' % (username_or_email, room_key, action), {})
        except urllib2.HTTPError, err:
            if err.code == 404:
                raise self.NotFound()
            raise

    def edit_user(self, username_or_email, user_info):
        try:
            self.client.post_json(
                'users/%s' % (username_or_email,), user_info)
        except urllib2.HTTPError, err:
            if err.code == 404:
                raise self.NotFound()
            elif err.code == 400:
                raise self.BadParams()
            elif err.code == 402:
                raise self.QuotaExceeded()
            elif err.code == 409:
                data = json.loads(err.read())
                if 'email' in data['conflicts']:
                    raise self.DuplicateEmail()
                elif 'group_id' in data['conflicts']:
                    raise self.BadGroup()
                elif 'plan_id' in data['conflicts']:
                    raise self.BadPlan()
            raise

    def delete_user(self, username_or_email):
        try:
            self.client.delete('users/%s' % (username_or_email,))
        except urllib2.HTTPError, err:
            if err.code == 404:
                raise self.NotFound()
            raise

    def send_activation_email(self, username_or_email, data={}):
        try:
            self.client.post_json('users/%s?action=sendactivationemail' % (
                username_or_email,), data)
        except urllib2.HTTPError, err:
            if err.code == 404:
                raise self.NotFound()
            elif err.code == 409:
                raise self.EmailNotSent()
            raise

