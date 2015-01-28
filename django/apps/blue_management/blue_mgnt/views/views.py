import os
import datetime
import codecs
import csv
import subprocess
import urllib.request, urllib.error, urllib.parse
from base64 import b64encode
import urllib.parse
import logging
import math
import os
import time
import bcrypt
from uuid import uuid4
from hashlib import sha256
from base64 import b64encode

from django.http import HttpResponse, HttpResponseForbidden, StreamingHttpResponse
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
from django.contrib.auth import authenticate, login, logout as django_logout
from django.core.paginator import Paginator, InvalidPage, EmptyPage
from django.conf import settings as django_settings
from django.contrib.auth.models import Group, Permission
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.decorators import permission_required
from django.forms.util import ErrorList
from django.forms.forms import NON_FIELD_ERRORS
from django.core.servers.basehttp import FileWrapper
from django.core.cache import cache

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
import collections

LOG = logging.getLogger('admin_actions')

MANAGEMENT_VM = getattr(django_settings, 'MANAGEMENT_VM', False)
APP_DIR = os.path.abspath(os.path.dirname(__file__))
SHARE_URL = os.getenv('SHARE_URL', 'https://spideroak.com')
SIZE_OF_GIGABYTE = 10 ** 9

PROFILE_LOG_BASE = '/opt/openmanage/django_profile'


def get_config_group(config, group_id):
    for group in config['groups']:
        if group['group_id'] == group_id:
            return group

def get_base_url(url=None):
    if not url:
        url = read_config_file()['api_root']
    split = urllib.parse.urlparse(url)
    return urllib.parse.urlunsplit((split.scheme, split.netloc, '', '', ''))


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
            except urllib.error.HTTPError:
                log.info('''Failed initial log in for "%s" as a superuser.
                         Password incorrect or unable to contact
                         accounts api''' % username)
                return None
            
        local_pass = config.get('local_password', '')
        hashed_pass = bcrypt.hashpw(password.encode('utf-8'), 
                                    local_pass.encode('utf-8')).decode('utf-8')
        if initial_auth or hashed_pass == local_pass:
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


class LoginForm(forms.Form):
    username = forms.CharField(max_length=90)
    password = forms.CharField(widget=forms.PasswordInput)

def hash_password(new_password):
    hash_ = sha256(new_password).digest()
    salt = '$2a$14$' + b64encode(hash_[:16]).rstrip('=').replace('+', '.')
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

                return redirect(request.GET.get('next', '/'))
            else:
                errors = form._errors.setdefault(NON_FIELD_ERRORS , ErrorList())
                errors.append('Invalid username or password')

    return render_to_response('login.html', dict(
        form=form,
        request_login=True,
    ),
    RequestContext(request))

def logout(request):
    django_logout(request)
    if 'username' in request.session:
        del request.session['username']

    return redirect('blue_mgnt:login')

def get_method_prefix(fun):
    key = "p/{0}".format(fun.__name__)
    val = cache.get(key)
    if val is None:
        return update_method_prefix(fun)
    return val

def update_method_prefix(fun):
    key = "p/{0}".format(fun.__name__)
    val = b64encode(uuid4().bytes).decode()
    cache.set(key, val)
    return val
    
def make_cache_key(fun, *args, **kwargs):
    spec = tuple(args) + tuple(v for k, v in sorted(kwargs.items()))
    key = ["c", fun.__name__, get_method_prefix(fun)]
    for i in spec:
        if i is None:
            key.append('')
        elif isinstance(i, (int, float)):
            key.append(str(i))
        else:
            key.append(b64encode(repr(i).encode()).decode())
    return "/".join(key)
        
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
        'update_enterprise_settings': [api.enterprise_settings],
        'create_group': [api.list_groups],
        'edit_group': [api.list_groups],
        'delete_group': [api.list_groups, api.list_users],
        'create_user': [api.list_users, api.get_user_count],
        'edit_user': [api.list_users],
        'delete_user': [api.list_users, api.get_user_count],
    }
    
    def cache_api(fun):
        def dec(*args, **kwargs):
            name = fun.__name__
            if name in FUNCTIONS_TO_INVALIDATE_CACHE:
                for f in FUNCTIONS_TO_INVALIDATE_CACHE[name]:
                    update_method_prefix(f)
            if name in FUNCTIONS_TO_CACHE:
                key = make_cache_key(fun, *args, **kwargs)
                value = cache.get(key)
                if not value:
                    value = fun(*args, **kwargs)
                    cache.set(key, value)
                return value
            else:
                return fun(*args, **kwargs)
        return dec

    for attr in dir(api):
        fun_ = getattr(api, attr)
        if (isinstance(fun_, collections.Callable) and 
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
            return redirect(reverse('blue_mgnt:login') + '?next=%s' % request.path)

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
def clear_cache(request, api, account_info, config, username): 
    cache.clear()
    return HttpResponse('Cache cleared')

@enterprise_required
def download_logs(request, api, account_info, config, username):
    date = datetime.datetime.now().strftime('%Y-%m-%d_%H:%M:%S')
    filename = 'openmanage-logs-%s.tar.bz2' % date
    path = '/opt/openmanage/tmp_logs/%s' % filename

    subprocess.call(['/opt/openmanage/bin/gather_logs.sh', date])

    response = StreamingHttpResponse(open(path, 'rb'),
                            content_type='application/bzip2')
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
    for page in range((account_info['total_users'] // user_limit) + 1):
        user_offset = user_limit * page
        if user_offset < account_info['total_users']:
            all_users = all_users + api.list_users(user_limit, user_offset)
    return all_users

@enterprise_required
def users_csv_download(request, api, account_info, config, username):
    log_admin_action(request, 'download user csv')
    users = list_users_paged(api, account_info)
    features = api.enterprise_features()

    response = HttpResponse(content_type='text/csv; charset=utf-8')
    response['Content-Disposition'] = 'attachment; filename=users.csv'

    utf8_writer = codecs.getwriter('utf8')(response)
    writer = csv.writer(utf8_writer)
    headers = ['name',
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
        row = [user['name'],
               user['email'],
               (user['share_id'] if user['share_id'] else ''),
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
            row = [user['username']] + row
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
    return render_to_response('manage.html', dict(
        user=request.user,
        username=username,
        account_info=account_info,
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


class Pagination(object):
    def __init__(self, count, page=1, per_page=25):
        self.page = 1
        try:
            self.page = int(page)
        except (TypeError, ValueError):
            pass
        self.per_page = per_page
        self.paginator = Paginator(list(range(count)), per_page, allow_empty_first_page=True)
        self.num_pages = self.paginator.num_pages
        last_page = self.paginator.num_pages
        try:
            self.paginator_page = self.paginator.page(self.page)
        except InvalidPage as e:
            self.paginator_page = self.paginator.page(last_page)
            self.page = last_page

        # populate self.page_range with list holding the page numbers to render in nav.
        # self.page_range is (currently) hard-coded to always contain 10 items
        # None values represent need to present '...' for skipped page ranges
        self.page_range = self.paginator.page_range
        if last_page <= 10:
            pass
        else:
            if self.page - 2 > 3:
                if self.page + 6 > last_page:
                    self.page_range = [1, None] + self.page_range[-8:]
                else:
                    self.page_range = [1, None] + self.page_range[self.page-3:self.page+3] + [None, last_page]
            else:
                self.page_range = self.paginator.page_range[:8] + [None, last_page]

    @property
    def query_offset(self):
        return max(0, self.paginator_page.start_index() - 1)


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
        item_count=list(range(item_count)),
        ref=ref,
        req=req,
        page=page,
    )
