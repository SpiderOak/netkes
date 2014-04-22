import unittest
from mock import Mock, MagicMock, sentinel, patch
import logging
import os

from django.test.client import Client
from django.contrib.auth.models import User, Group
from django.conf import settings
from django.contrib.auth.models import Permission
from django.http import HttpResponse

settings.ADMIN_ACTIONS_LOG_FILE = ''

from blue_mgnt.views import views, managementvm
from blue_mgnt import models
from netkes.account_mgr.accounts_api import Api

os.environ['OPENMANAGE_CONFIGDIR'] = '/opt/openmanage/etc/'

GOT_PERMS = False
DELETE_USER_DATA = {'form-0-orig_email': 'test0@test', 
                    'form-0-DELETE': 'on', 
                    'form-1-orig_email': 'test1@test',
                    'form-TOTAL_FORMS': 1, 
                    'form-INITIAL_FORMS': 1 
                    }
USER_DETAIL_USER_DATA = {u'name': u'test', 
                         u'email': u'test@test.com',
                         u'bonus_gigs': '5', 
                         u'form': u'edit_user',
                         u'group_id': u'1',
                         u'enabled': True,
                         }

def get_features(**kw):
    features = {u'group_permissions': True, 
                u'netkes': True, 
                u'ldap': True, 
                u'signup_restrictions': True, 
                u'email_as_username': True
               }
    features.update(kw)
    return features

def get_perms():
    global GOT_PERMS
    if not GOT_PERMS:
        from blue_mgnt import permissions
        GOT_PERMS = True

def setUpAuth(codenames=[]):
    user = User.objects.get_or_create(username='test', password='not_used')[0]
    user.user_permissions = Permission.objects.filter(codename__in=codenames)
    group = Group.objects.get_or_create(name='test_group')[0]
    admin_group = models.AdminGroup.objects.get_or_create(pk=group.id,
                                                          user_group_id=group.id)[0]
    user.groups.add(group)
    views.LdapBackend.authenticate = MagicMock()
    views.LdapBackend.authenticate.return_value = user 


class TestViewAuth(unittest.TestCase):
    def setUp(self):
        get_perms()
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

    def test_escrow_login_available_with_permission(self):
        self.login(['can_view_user_data'])
        response = self.client.get('/escrowlogin/test/')
        self.assertEqual(response.status_code, 302)

    @patch.object(Api, 'delete_user')
    def test_unable_to_edit_users_without_permission(self, delete_user):
        self.login()
        response = self.client.post('/users/', DELETE_USER_DATA)
        self.assertFalse(delete_user.called)

#    @patch.object(Api, 'delete_user')
#    def test_able_to_edit_users_with_permission(self):
#        self.login(['can_manage_users'])
#        response = self.client.post('/users/', DELETE_USER_DATA)
#        delete_user.assert_called_once_with('test@test')

    @patch.object(Api, 'list_shares', return_value=[])
    @patch.object(Api, 'list_devices', return_value=[])
    @patch.object(Api, 'get_user', return_value=dict(bonus_bytes=5 * 10 ** 9))
    @patch.object(Api, 'edit_user')
    def test_unable_to_edit_user_detail_without_permission(self, edit_user, get_user, 
                                                           list_devices, list_shares):
        self.login()
        response = self.client.post('/users/test@test/', USER_DETAIL_USER_DATA)
        self.assertFalse(edit_user.called)

    @patch.object(views, 'render_to_response', return_value=HttpResponse('good'))
    @patch.object(Api, 'enterprise_features', return_value=get_features(ldap=False))
    @patch.object(Api, 'list_groups', return_value=[dict(group_id=1, name='test')])
    @patch.object(Api, 'list_shares', return_value=[])
    @patch.object(Api, 'list_devices', return_value=[])
    @patch.object(Api, 'get_user')
    @patch.object(Api, 'edit_user')
    def test_able_to_edit_user_detail_with_permission(self, edit_user, get_user, 
                                                      list_devices, list_shares,
                                                      list_groups, enterprise_features,
                                                      render_to_response):
        get_user.return_value = {
            'username': 'test', 
            'group_id': 1, 
            'bonus_bytes': 1,
        }
        self.login(['can_manage_users'])
        response = self.client.post('/users/test@test/', USER_DETAIL_USER_DATA)

        call_data = dict(USER_DETAIL_USER_DATA)
        del call_data['form']
        del call_data['bonus_gigs']

        edit_user.assert_called_once_with(u'test@test', call_data)











