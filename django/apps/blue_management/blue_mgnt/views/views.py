import os
import datetime
import csv
import subprocess
import urllib2
from base64 import b32encode
import urlparse
import ldap
import logging
import math
import hotshot
import os
import time
import bcrypt
from hashlib import sha256
from base64 import b64encode

from django.http import HttpResponse, HttpResponseForbidden
from django.shortcuts import redirect, render_to_response
from django.core.urlresolvers import reverse
from django.core.exceptions import ObjectDoesNotExist
from django.template.context import Context
from django.template import RequestContext, TemplateDoesNotExist
from django import forms
from django.forms.models import modelformset_factory
from django.forms.formsets import formset_factory
from django.forms import ModelForm
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login
from django.core.paginator import Paginator, InvalidPage, EmptyPage
from django.conf import settings as django_settings
from django.contrib.auth.models import Group, Permission
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.decorators import permission_required
from django.forms.util import ErrorList
from django.forms.forms import NON_FIELD_ERRORS
from django.core.servers.basehttp import FileWrapper
from django.core.cache import cache

from interval.forms import IntervalFormField
from mako.lookup import TemplateLookup
from mako import exceptions

from blue_mgnt import models
from netkes.account_mgr.accounts_api import Api
from netkes.account_mgr.billing_api import BillingApi
from netkes.netkes_agent import config_mgr
from netkes.common import read_config_file
from netkes.account_mgr.user_source import ldap_source, local_source
from netkes import account_mgr
from key_escrow import server
from Pandora import serial
from Crypto.Util.RFC1751 import key_to_english

LOG = logging.getLogger('admin_actions')

MANAGEMENT_VM = getattr(django_settings, 'MANAGEMENT_VM', False)
APP_DIR = os.path.abspath(os.path.dirname(__file__))
SHARE_URL = os.getenv('SHARE_URL', 'https://spideroak.com')
SIZE_OF_GIGABYTE = 10 ** 9

PROFILE_LOG_BASE = '/opt/openmanage/django_profile'


def profile(log_file):
    """Profile some callable.

    This decorator uses the hotshot profiler to profile some callable (like
    a view function or method) and dumps the profile data somewhere sensible
    for later processing and examination.

    It takes one argument, the profile log name. If it's a relative path, it
    places it under the PROFILE_LOG_BASE. It also inserts a time stamp into the
    file name, such that 'my_view.prof' become 'my_view-20100211T170321.prof',
    where the time stamp is in UTC. This makes it easy to run and compare
    multiple trials.
    """

    if not os.path.isabs(log_file):
        log_file = os.path.join(PROFILE_LOG_BASE, log_file)

    def _outer(f):
        def _inner(*args, **kwargs):
            # Add a timestamp to the profile output when the callable
            # is actually called.
            (base, ext) = os.path.splitext(log_file)
            base = base + "-" + time.strftime("%Y%m%dT%H%M%S", time.gmtime())
            final_log_file = base + ext

            prof = hotshot.Profile(final_log_file)
            try:
                ret = prof.runcall(f, *args, **kwargs)
            finally:
                prof.close()
            return ret

        return _inner
    return _outer

def get_config_group(config, group_id):
    for group in config['groups']:
        if group['group_id'] == group_id:
            return group

def get_base_url(url=None):
    if not url:
        url = read_config_file()['api_root']
    split = urlparse.urlparse(url)
    return urlparse.urlunsplit((split.scheme, split.netloc, '', '', ''))


class LoginForm(forms.Form):
    username = forms.CharField(max_length=45)
    password = forms.CharField(widget=forms.PasswordInput)

    def clean(self):
        cleaned_data = super(LoginForm, self).clean()

        username = cleaned_data.get('username')
        password = cleaned_data.get('password')


def log_admin_action(request, message):
    if request.user.is_superuser:
        group_name = 'superuser'
    else:
        group_name = request.user.groups.all()[0].name
    LOG.info('%s (%s): %s' % (request.user.username, group_name, message))

class NetkesBackend(ModelBackend):
    def authenticate_superuser(self, username, password):
        log = logging.getLogger('admin_actions.authenticate_superuser')
        log.info('Attempting to log "%s" in as a superuser' % username)

        config = read_config_file()
        if config['api_user'] and (username != config['api_user']):
            log.info('Username "%s" does not match superuser username' % username)
            return None

        initial_auth = False
        if not config['api_user']:
            new_pass, api_pass = hash_password(password)
            api = Api.create(
                django_settings.ACCOUNT_API_URL,
                username,
                api_pass,
            )
            try:
                api.ping()
                initial_auth = True
            except urllib2.HTTPError:
                log.info('''Failed initial log in for "%s" as a superuser.
                         Password incorrect or unable to contact
                         accounts api''' % username)
                return None
            
        local_pass = config.get('local_password', '')
        if initial_auth or bcrypt.hashpw(password, local_pass) == local_pass:
            try:
                user = User.objects.get(username=username)
            except ObjectDoesNotExist:
                user = User(username=username, password='not used')
                user.is_staff = True
                user.is_superuser = True
                user.save()
            user.user_permissions = Permission.objects.filter(
                content_type__app_label='blue_mgnt',
                content_type__model='AccountsApi'
            )

            return user
        else:
            msg = '''Failed to log in "%s" as a superuser. Password incorrect.
            ''' % username
            log.info(msg)
            return None

    def authenticate_netkes(self, username, password):
        log = logging.getLogger('admin_actions.authenticate_netkes')
        log.info('Attempting to log in "%s" through netkes' % username)

        config = read_config_file()
        api = get_api(config)
        if account_mgr.authenticator(config, username, password, False):
            api_user = api.get_user(username)
            group_id = api_user['group_id']
            config_group = get_config_group(config, group_id)
            if not config_group['admin_group']:
                log.info('Username "%s" is not in an admin group' % username)
                return None
            try:
                admin_group = models.AdminGroup.objects.get(user_group_id=group_id)
            except models.AdminGroup.DoesNotExist:
                log.info('Unable to find admin group for group %s' % group_id)
                return None
            group = Group.objects.get(pk=admin_group.group_id)
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                user = User(username=username, password='not used')
                user.save()
            user.groups.add(group)
            return user
        else:
            msg = '''Failed to authenticate "%s". Username or password incorrect.
            ''' % username 
            log.info(msg)

    def authenticate(self, username=None, password=None):
        user = self.authenticate_superuser(username, password)
        if user:
            return user

        config = read_config_file()
        if config['api_user']:
            return self.authenticate_netkes(username, password)
        return None

    def get_user(self, user_id):
            try:
                return User.objects.get(pk=user_id)
            except User.DoesNotExist:
                return None

LdapBackend = NetkesBackend


class LoginForm(forms.Form):
    username = forms.CharField(max_length=90)
    password = forms.CharField(widget=forms.PasswordInput)

def hash_password(new_password):
    hash_ = sha256(new_password).digest()
    salt = '$2a$14$' + b64encode(hash_[:16]).rstrip('=')
    new_pass = bcrypt.hashpw(new_password, salt)
    api_pass = new_pass[len(salt):]

    return new_pass, api_pass

def initial_setup(username, password):
    new_pass, api_pass = hash_password(password)

    config_mgr_ = config_mgr.ConfigManager(config_mgr.default_config())
    config_mgr_.config['api_user'] = username
    config_mgr_.config['api_password'] = api_pass
    config_mgr_.config['local_password'] = new_pass
    config_mgr_.apply_config()

def create_initial_group():
    config_mgr_ = config_mgr.ConfigManager(config_mgr.default_config())
    api = get_api(config_mgr_.config)

    plans = api.list_plans()
    unlimited = [x for x in plans if x['storage_bytes'] == 1000000001000000000]
    if unlimited:
        info = api.info()
        data = {
            'name': info['company_name'],
            'plan_id': unlimited[0]['plan_id'],
            'webapi_enable': True,
            'check_domain': False,
        }
        group_id = api.create_group(data)
        data = dict(group_id=group_id,
                    type='dn',
                    ldap_id='',
                    priority=0,
                    user_source='local',
                    admin_group=False,
                   )
        config_mgr_.config['groups'].append(data)
        config_mgr_.apply_config()

def login_user(request):
    form = LoginForm()
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            password = form.cleaned_data['password']
            username = form.cleaned_data['username'].strip()
            user = authenticate(username=username,
                                password=password)
            if user and user.is_active:
                login(request, user)
                remote_addr = request.META['REMOTE_ADDR']
                log_admin_action(request, 'logged in')# from ip: %s' % remote_addr)
                config = read_config_file()

                if not config['api_password']:
                    initial_setup(username, password)
                    config = read_config_file()
                    api = get_api(config)
                    if api.backup():
                        log_admin_action(request, 'restoring from backup')
                        subprocess.call(['/opt/openmanage/bin/run_restore_omva.sh',])
                    elif not config['groups']:
                        create_initial_group()

                config_mgr_ = config_mgr.ConfigManager(config_mgr.default_config())
                api = get_api(config_mgr_.config)
                subprocess.call(['/opt/openmanage/bin/first_setup.sh', 
                                 api.info()['brand_identifier']])

                request.session['username'] = username

                return redirect('blue_mgnt:index')
            else:
                errors = form._errors.setdefault(NON_FIELD_ERRORS , ErrorList())
                errors.append('Invalid username or password')

    return render_to_response('login.html', dict(
        form=form,
        request_login=True,
    ),
    RequestContext(request))

def logout(request):
    if 'username' in request.session:
        del request.session['username']

    return redirect('blue_mgnt:login')

def validate(request):
    '''
    >>> from django.test.client import Client
    >>> c = Client()
    >>> r = c.get(reverse(validate))
    >>> r.status_code
    403

    '''
    try:
        user = authenticate(hmac=request.GET['hmac'],
                            ctime=request.GET['time'],
                            partner_id=request.GET['partner'])
    except KeyError:
        pass
    else:
        if user is not None:
            login(request, user)
            return redirect('blue_mgnt:index')
    return HttpResponseForbidden("Enterprise management link is expired or invalid.", mimetype="text/plain")

def get_api(config):
    api = Api.create(
        django_settings.ACCOUNT_API_URL,
        config['api_user'],
        config['api_password'],
    )

    FUNCTIONS_TO_CACHE = [
        'list_plans',
        'quota',
        'info',
        'enterprise_features',
        'enterprise_settings',
        'list_groups',
        'list_shares_for_brand',
        'get_user_count',
        'list_devices',
        'list_shares',
        'list_users',
    ]
    FUNCTIONS_TO_INVALIDATE_CACHE = {
        'update_enterprise_settings': ['enterprise_settings'],
        'create_group': ['list_groups'],
        'edit_group': ['list_groups'],
        'delete_group': ['list_groups', 'list_users'],
        'create_user': ['list_users'],
        'edit_user': ['list_users'],
        'delete_user': ['list_users'],
    }
    
    def check_list_users(name, args, kwargs):
        if (name == 'list_users' and 
            args == (25, 0) 
            and not kwargs):
            return True
        return False

    def cache_api(fun):
        def dec(*args, **kwargs):
            name = fun.__name__
            if name in FUNCTIONS_TO_INVALIDATE_CACHE:
                for f in FUNCTIONS_TO_INVALIDATE_CACHE[name]:
                    cache.delete(f)
            if name in FUNCTIONS_TO_CACHE or check_list_users(name, args, kwargs):
                value = cache.get(name)
                if not value:
                    value = fun(*args, **kwargs)
                    cache.set(name, value)
                return value
            else:
                return fun(*args, **kwargs)
        return dec

    for attr in dir(api):
        fun_ = getattr(api, attr)
        if (callable(fun_) and 
            (attr in FUNCTIONS_TO_CACHE or 
             attr in FUNCTIONS_TO_INVALIDATE_CACHE)):
            setattr(api, attr, cache_api(fun_))
    return api

def get_billing_api(config):
    billing_api = BillingApi.create(
        django_settings.BILLING_API_URL,
        config['api_user'],
        config['api_password'],
    )
    return billing_api


def get_billing_info(config):
    billing_info = cache.get('billing_info')
    if not billing_info:
        billing_api = get_billing_api(config)
        billing_info = billing_api.billing_info()
        cache.set('billing_info', billing_info, 60 * 15)
    return billing_info


def enterprise_required(fun):
    def new_fun(request, *args, **kwargs):
        if not request.session.get('username', False):
            return redirect('blue_mgnt:login')

        config = read_config_file()
        api = get_api(config)
        account_info = dict()
        quota = api.quota()
        account_info['device_count'] = quota['device_count']
        account_info['share_count'] = quota['share_count']
        account_info['space_used'] = quota['bytes_used']
        account_info['space_allocated'] = quota['bytes_allocated']
        account_info['space_available'] = (quota['bytes_available'] or 0) / (10.0 ** 9)
        account_info['show_available'] = True
        if not account_info['space_available']:
            account_info['show_available'] = False
            account_info['space_available'] = account_info['space_allocated']
        user_count = api.get_user_count()
        account_info['total_users'] = user_count
        account_info['total_groups'] = len(config['groups'])
        account_info['total_auth_codes'] = models.AdminSetupTokensUse.objects.count()
        account_info['api_user'] = config['api_user']
        account_info['info'] = api.info()
        
        with open('/opt/openmanage/etc/OpenManage_version.txt') as f:
            account_info['version'] = f.readlines()[0]
        return fun(request, api, account_info, config,
                   request.session['username'], *args, **kwargs)
    return new_fun

@enterprise_required
def download_logs(request, api, account_info, config, username):
    date = datetime.datetime.now().strftime('%Y-%m-%d_%H:%M:%S')
    filename = 'openmanage-logs-%s.tar.bz2' % date
    path = '/opt/openmanage/tmp_logs/%s' % filename

    subprocess.call(['/opt/openmanage/bin/gather_logs.sh', date])

    response = HttpResponse(FileWrapper(open(path)),
                            mimetype='application/bzip2')
    response['Content-Disposition'] = 'attachment; filename=%s' % filename
    return response

@enterprise_required
def users_csv(request, api, account_info, config, username):
    return render_to_response('csv.html', dict(
        features=api.enterprise_features(),
        account_info=account_info,
    ),
    RequestContext(request))

def list_users_paged(api, account_info):
    all_users = []
    user_limit = 1000
    for page in range((account_info['total_users'] / user_limit) + 1):
        user_offset = user_limit * page
        if user_offset < account_info['total_users']:
            all_users = all_users + api.list_users(user_limit, user_offset)
    return all_users

@enterprise_required
def users_csv_download(request, api, account_info, config, username):
    log_admin_action(request, 'download user csv')
    users = list_users_paged(api, account_info)
    features = api.enterprise_features()

    response = HttpResponse(mimetype='text/csv')
    response['Content-Disposition'] = 'attachment; filename=users.csv'

    writer = csv.writer(response)
    headers = [ 'name',
               'email',
               'share_id',
               'creation_time',
               'last_login',
               'bytes_stored',
               'storage_bytes',
               'group_id',
               'enabled']
    if not features['email_as_username']:
        headers = ['username'] + headers
    writer.writerow(headers)
    for user in users:
        row = [user['name'].encode('utf-8'),
               user['email'].encode('utf-8'),
               (user['share_id'] if user['share_id'] else '').encode('utf-8'),
               user['creation_time'],
               user['last_login'],
               user['bytes_stored'],
               user['storage_bytes'],
               user.get('group_id', ''),
               user['enabled']]
        if user['creation_time']:
            row[3] = datetime.datetime.fromtimestamp(user['creation_time'])
        if user['last_login']:
            row[4] = datetime.datetime.fromtimestamp(user['last_login'])
        if not features['email_as_username']:
            row = [user['username'].encode('utf-8')] + row
        writer.writerow(row)

    return response

class ReadOnlyWidget(forms.Widget):
    def render(self, name, value, attrs):
        final_attrs = self.build_attrs(attrs, name=name)
        if hasattr(self, 'initial'):
            value = self.initial
        return "%s" % (value if value != None else '')

    def _has_changed(self, initial, data):
        return False

def process_row(row):
    return dict(name=row['name'],
                plan_id=int(row['plan_id']),
                check_domain=bool(row.get('check_domain', True)),
                webapi_enable=bool(row.get('webapi_enable', True)),
               )

@enterprise_required
@permission_required('blue_mgnt.can_manage_shares', raise_exception=True)
def shares(request, api, account_info, config, username, saved=False):
    features = api.enterprise_features()
    opts = api.enterprise_settings()
    page = int(request.GET.get('page', 1))

    user_limit = 25
    user_offset = user_limit * (page - 1)
    users = api.list_shares_for_brand(user_limit, user_offset)
    next_page = len(users) == user_limit

    if request.method == 'POST':
        if request.POST.get('form', '') == 'edit_share':
            email = request.POST['email']
            room_key = request.POST['room_key']
            enable = request.POST['enabled'] == 'False'
            msg = 'edit share %s for user %s. Action %s share' % \
                    (room_key, email, 'enable' if enable else 'disable')
            log_admin_action(request, msg)
            api.edit_share(email, room_key, enable)
            return redirect('blue_mgnt:shares_saved')
        if request.POST.get('form', '') == 'edit_shares':
            sharing_enabled = request.POST['sharing_enabled'] == 'False'
            log_admin_action(request, 'set sharing enabled to %s ' % sharing_enabled)
            api.update_enterprise_settings(dict(sharing_enabled=sharing_enabled))
            return redirect('blue_mgnt:shares_saved')

    return render_to_response('shares.html', dict(
        share_url=get_base_url(),
        sharing_enabled=opts['sharing_enabled'],
        page=page,
        next_page=next_page,
        datetime=datetime,
        user=request.user,
        username=username,
        features=features,
        users=users,
        account_info=account_info,
        saved=saved,
    ),
    RequestContext(request))

@enterprise_required
@permission_required('blue_mgnt.can_manage_shares', raise_exception=True)
def share_detail(request, api, account_info, config, username, email,
                 room_key, saved=False):
    api_user = api.get_user(email)
    share = api.get_share(email, room_key)

    if request.method == 'POST':
        if request.POST.get('form', '') == 'edit_share':
            enable = request.POST['enabled'] == 'False'
            msg = 'edit share %s for user %s. Action %s share' % \
                    (room_key, email, 'enable' if enable else 'disable')
            log_admin_action(request, msg)
            api.edit_share(email, room_key, enable)
            return redirect('blue_mgnt:share_detail', email, room_key)

    return render_to_response('share_detail.html', dict(
        username=username,
        share_url=get_base_url(),
        share=share,
        api_user=api_user,
        account_info=account_info,
    ),
    RequestContext(request))


@enterprise_required
def reports(request, api, account_info, config, username, saved=False):
    total_users = float(account_info['total_users'] or 1)
    average_stored = (account_info['space_used'] or  0) / total_users
    average_stored = round(average_stored / SIZE_OF_GIGABYTE, 2)
    average_num_devices = round((account_info['device_count'] or 0) / total_users, 2)
    return render_to_response('reports.html', dict(
        username=username,
        account_info=account_info,
        average_stored=average_stored,
        average_num_devices=average_num_devices,
        device_count=account_info['device_count'],
        share_count=account_info['share_count'],
    ),
    RequestContext(request))

@enterprise_required
def manage(request, api, account_info, config, username):
    account_name = config['api_user'].replace("_", " ")
    return render_to_response('manage.html', dict(
        user=request.user,
        username=username,
        account_info=account_info,
        account_name=account_name,
        billing_info=get_billing_info(config),
    ),
    RequestContext(request))

@enterprise_required
def fingerprint(request, api, account_info, config, username):
    brand_identifier = api.info()['brand_identifier']

    layers = serial.loads(server.get_escrow_layers(brand_identifier))

    # Generate fingerprint
    h = sha256()
    for key_id, key in layers:
        s = '{0}{1}'.format(key_id, key.publickey().exportKey('DER'))
        h.update(s)
    fingerprint = enumerate(key_to_english(h.digest()).split(' '))
    fingerprint = ' '.join([word for x, word in fingerprint \
                            if x % 2 == 0])
    
    return render_to_response('fingerprint.html', dict(
        user=request.user,
        username=username,
        account_info=account_info,
        fingerprint=fingerprint,
    ),
    RequestContext(request))

# Benny's da_paginator
def pageit(sub, api, page, extra):
    if not extra:
        extra=()

    funcmap = {
        'users': lambda: api.get_user_count(),
        'groups': lambda: len(api.list_groups()),
        'shares': lambda: len(api.list_shares_for_brand()),
        'logs': lambda: extra,
    }
    try:
        all_items = funcmap[sub]()
    except LookupError:
        return False

    limit = 25
    item_count = int(math.ceil(all_items / float(limit)))
    if page > item_count:
        page = item_count
    elif page < 1:
        page = 1

    ref='%d:%d' %(page, page+6)
    req='blue_mgnt:%s' % sub

    return dict(
        item_count=range(item_count),
        ref=ref,
        req=req,
        page=page,
    )
