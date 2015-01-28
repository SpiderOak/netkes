import unittest
from mock import Mock, MagicMock, sentinel, patch
import logging
import os

from django.test import TestCase
from django.test.client import Client
from django.contrib.auth.models import User, Group
from django.conf import settings
from django.contrib.auth.models import Permission
from django.http import HttpResponse

settings.ADMIN_ACTIONS_LOG_FILE = ''

from blue_mgnt import permissions
from blue_mgnt.views import views, managementvm, users
from blue_mgnt import models
from netkes.account_mgr.accounts_api import Api

os.environ['OPENMANAGE_CONFIGDIR'] = '/opt/openmanage/etc/'

DELETE_USER_DATA = {'delete_user-0-orig_email': 'test0@test', 
                    'delete_user-0-DELETE': 'on', 
                    'delete_user-TOTAL_FORMS': 1, 
                    'delete_user-INITIAL_FORMS': 1, 
                    'delete_user-MIN_NUM_FORMS': 0, 
                    'delete_user-MAX_NUM_FORMS': 1000, 
                    'tmp_user-TOTAL_FORMS': 1, 
                    'tmp_user-INITIAL_FORMS': 1, 
                    'tmp_user-0-orig_email': 'test0@test', 
                    'tmp_user-0-group_id': 1, 
                    }

USER_DETAIL_USER_DATA = {'name': 'test', 
                         'email': 'test@test.com',
                         'bonus_gigs': '5', 
                         'form': 'edit_user',
                         'group_id': '1',
                         'enabled': True,
                         }

USERS = [
    {
        'username': 'test',
        'email': 'test@test.com',
        'name': 'test',
        'bytes_stored': 0,
        'creation_time': 0,
        'last_login': 0,
        'group_id': 0,
        'enabled': True,
    }
]

def get_features(**kw):
    features = {'group_permissions': True, 
                'netkes': True, 
                'ldap': True, 
                'signup_restrictions': True, 
                'email_as_username': True
               }
    features.update(kw)
    return features

def setUpAuth(codenames=[]):
    user = User.objects.get_or_create(username='test', password='not_used')[0]
    user.user_permissions = Permission.objects.filter(codename__in=codenames)
    gname = codenames[0] if codenames else 'no code'
    group = Group.objects.get_or_create(name=gname)[0]
    admin_group = models.AdminGroup.objects.get_or_create(pk=group.id,
                                                          user_group_id=group.id)[0]
    user.groups.add(group)
    user.backend = 'blue_mgnt.views.views.NetkesBackend'
    views.authenticate = MagicMock()
    views.authenticate.return_value = user 

def spec():
    pass

class TestViewAuth(TestCase):
    def setUp(self):
        permissions.create_permissions()
        self.client = Client()

    def login(self, codenames=[]):
        setUpAuth(codenames)
        response = self.client.post('/login/', dict(username='test', password='a'))

    def test_must_be_logged_in(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 302)

    def test_login_allows_access(self):
        self.login()
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)

    def test_auth_codes_access_denied_without_permission(self):
        self.login()
        response = self.client.get('/codes/')
        self.assertEqual(response.status_code, 403)

    def test_auth_codes_access_granted_with_permission(self):
        self.login(['can_manage_auth_codes'])
        response = self.client.get('/codes/')
        self.assertEqual(response.status_code, 200)

    def test_view_groups_access_denied_without_permission(self):
        self.login()
        response = self.client.get('/groups/')
        self.assertEqual(response.status_code, 403)

    def test_view_groups_access_granted_with_permission(self):
        self.login(['can_view_groups'])
        response = self.client.get('/groups/')
        self.assertEqual(response.status_code, 200)

    def test_shares_access_denied_without_permission(self):
        self.login()
        response = self.client.get('/shares/')
        self.assertEqual(response.status_code, 403)

    def test_shares_access_granted_with_permission(self):
        self.login(['can_manage_shares'])
        response = self.client.get('/shares/')
        self.assertEqual(response.status_code, 200)

    def test_view_settings_access_denied_without_permission(self):
        self.login()
        response = self.client.get('/settings/')
        self.assertEqual(response.status_code, 403)

    def test_view_settings_access_granted_with_permission(self):
        self.login(['can_view_settings'])
        response = self.client.get('/settings/')
        self.assertEqual(response.status_code, 200)
        #print('\n\n\n\n{}'.format(response.redirect_chain))

    def test_password_access_denied_without_permission(self):
        self.login()
        response = self.client.get('/settings/password/')
        self.assertEqual(response.status_code, 403)

    def test_password_access_granted_with_permission(self):
        self.login(['can_manage_settings'])
        response = self.client.get('/settings/password/')
        self.assertEqual(response.status_code, 200)

    def test_escrow_login_unavailable_without_permission(self):
        self.login()
        response = self.client.get('/escrowlogin/test/')
        self.assertEqual(response.status_code, 403)

    @patch.object(Api, 'get_user', return_value=dict(email='test@test.com'))
    def test_escrow_login_available_with_permission(self, get_user):
        self.login(['can_view_user_data'])
        response = self.client.get('/escrowlogin/test/')
        self.assertEqual(response.status_code, 302)

    @patch.object(Api, 'list_users', return_value=USERS, spec=spec)
    @patch.object(Api, 'delete_user')
    def test_unable_to_edit_users_without_permission(self, delete_user, list_users):
        self.login()
        response = self.client.post('/users/', DELETE_USER_DATA)
        self.assertFalse(delete_user.called)

#    @patch.object(Api, 'delete_user')
#    def test_able_to_edit_users_with_permission(self):
#        self.login(['can_manage_users'])
#        response = self.client.post('/users/', DELETE_USER_DATA)
#        delete_user.assert_called_once_with('test@test')

    @patch.object(Api, 'list_shares', return_value=[], spec=spec)
    @patch.object(Api, 'list_devices', return_value=[], spec=spec)
    @patch.object(Api, 'get_user', return_value=dict(group_id=1, 
                                                     username='test',
                                                     bonus_bytes=5 * 10 ** 9))
    @patch.object(Api, 'edit_user')
    def test_unable_to_edit_user_detail_without_permission(self, edit_user, get_user, 
                                                           list_devices, list_shares):
        self.login()
        response = self.client.post('/users/test@test/', USER_DETAIL_USER_DATA)
        self.assertFalse(edit_user.called)

    @patch.object(users, 'get_local_groups', return_value=[(1, 'test')])
    @patch.object(users, 'is_local_user', return_value=True)
    @patch.object(views, 'render_to_response', return_value=HttpResponse('good'))
    @patch.object(Api, 'enterprise_features', return_value=get_features(ldap=False), spec=spec)
    @patch.object(Api, 'list_groups', return_value=[dict(group_id=1, name='test')], spec=spec)
    @patch.object(Api, 'list_shares', return_value=[], spec=spec)
    @patch.object(Api, 'list_devices', return_value=[], spec=spec)
    @patch.object(Api, 'get_user', spec=spec)
    @patch.object(Api, 'edit_user', spec=spec)
    def test_able_to_edit_user_detail_with_permission(self, edit_user, get_user, 
                                                      list_devices, list_shares,
                                                      list_groups, enterprise_features,
                                                      render_to_response,
                                                      is_local_user,
                                                      get_local_groups):
        get_user.return_value = {
            'username': 'test', 
            'group_id': 1, 
            'bonus_bytes': 1,
        }
        self.login(['can_manage_users'])
        response = self.client.post('/users/test@test.com/', USER_DETAIL_USER_DATA)

        call_data = dict(USER_DETAIL_USER_DATA)

        self.assertTrue(edit_user.called)
        call_args = edit_user.call_args[0][1]
        for key in call_args.keys():
            self.assertEqual(call_args[key], call_data[key])











