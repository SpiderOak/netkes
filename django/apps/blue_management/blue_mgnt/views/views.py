import os
import datetime
import csv
from subprocess import call
import urllib2
from base64 import b32encode
import urlparse
import ldap
import logging

from django.http import HttpResponse, HttpResponseForbidden
from django.shortcuts import redirect
from django.shortcuts import render_to_response as django_render_to_response
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

from interval.forms import IntervalFormField
from mako.lookup import TemplateLookup
from mako import exceptions
from IPy import IP

from blue_mgnt import models
from so_common.regex import new_user_value_re_tests
from so_common.forms import PasswordForm
from netkes.account_mgr.accounts_api import Api
from netkes.netkes_agent import config_mgr
from netkes.common import read_config_file
from netkes.account_mgr.user_source import ldap_source, local_source
from netkes import account_mgr

LOG = logging.getLogger('admin_actions')

MANAGEMENT_VM = getattr(django_settings, 'MANAGEMENT_VM', False)
APP_DIR = os.path.abspath(os.path.dirname(__file__))
LOOKUP = TemplateLookup(directories=[os.path.join(APP_DIR, '../mako_templates')],
                        input_encoding='utf-8',
                        output_encoding='utf-8',
                        encoding_errors='replace')
SHARE_URL = os.getenv('SHARE_URL', 'https://spideroak.com')
SIZE_OF_GIGABYTE = 10 ** 9

def render_to_response(template, data=None, context=None):
    # pass ?force_template=mako to force using mako template
    # or ?force_template=django to force using Django
    try:
        force_template = context['request'].GET.get('force_template')
    except (AttributeError, KeyError):
        force_template = None

    if force_template != 'mako':
        try:
            return django_render_to_response(template, data, context_instance=context)
        except TemplateDoesNotExist as e:
            if force_template == 'django':
                raise e

    template = LOOKUP.get_template(template)
    if data is None:
        data = {}
    if context is None:
        context = Context(data)
    else:
        context.update(data)
    tmpl_data = {}
    for d in context:
        tmpl_data.update(d)
    tmpl_data['reverse'] = reverse
    tmpl_data['management_vm'] = getattr(django_settings, 'MANAGEMENT_VM', False)
    tmpl_data['private_cloud'] = getattr(django_settings, 'PRIVATE_CLOUD', False)
    try:
        return HttpResponse(template.render(**tmpl_data))
    except Exception, e:
        if django_settings.DEBUG:
            return HttpResponse(exceptions.text_error_template().render())
        else:
            raise

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
        if username != config['api_user']:
            log.info('Username "%s" does not match superuser username' % username)
            return None

        api = Api.create(
            django_settings.ACCOUNT_API_URL,
            username,
            password,
        )
        try:
            api.ping()
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
            if not config['api_password']:
                config_mgr_ = config_mgr.ConfigManager(config_mgr.default_config())
                config_mgr_.config['api_password'] = password
                config_mgr_.apply_config()


            return user
        except urllib2.HTTPError:
            log.info('''Failed to log in "%s" as a superuser. 
                        Password incorrect or unable to contact 
                        accounts api''' % username) 
            
            return None

    def authenticate_ldap(self, username, password):
        config = read_config_file()
        conn = ldap.initialize(config['dir_uri'])
        try:
            auth_user = ldap_source.get_auth_username(config, username)
            conn.simple_bind_s(auth_user, password)
            group = False
            ldap_conn = ldap_source.OMLDAPConnection(config["dir_uri"],
                                                     config["dir_base_dn"],
                                                     config["dir_user"],
                                                     config["dir_password"])
            for admin_group in models.AdminGroup.objects.all():
                group = ldap_source.LdapGroup.get_group(
                    ldap_conn,
                    config,
                    admin_group.ldap_dn,
                    admin_group.ldap_dn,
                )
                for user in group.userlist():
                    key = 'email'
                    if 'username' in user:
                        key = 'username'
                    if user[key] == username:
                        group = Group.objects.get(pk=admin_group.group_id)
                        break

            if not group:
                return None
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                user = User(username=username, password='not used')
                user.save()
            user.groups.add(group)
            return user
        except Exception, e:
            return None

    def authenticate_netkes(self, username, password):
        log = logging.getLogger('admin_actions.authenticate_netkes')
        log.info('Attempting to log in "%s" through netkes' % username) 

        config = read_config_file()
        api = get_api(config)
        if account_mgr.authenticator(config, username, password, False):
            api_user = api.get_user(username)
            try:
                admin_group = models.AdminGroup.objects.get(user_group_id=api_user['group_id'])
            except models.AdminGroup.DoesNotExist:
                log.info('Username "%s" is not in an admin group' % username)
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
            log.info('''Failed to authenticate "%s". Username or password 
                        incorrect.''' % username) 

    def authenticate(self, username=None, password=None):
        user = self.authenticate_superuser(username, password)
        if user:
            return user

        return self.authenticate_netkes(username, password)

    def get_user(self, user_id):
            try:
                return User.objects.get(pk=user_id)
            except User.DoesNotExist:
                return None

LdapBackend = NetkesBackend


class LoginForm(forms.Form):
    username = forms.CharField(max_length=90)
    password = forms.CharField(widget=forms.PasswordInput)

def login_user(request):
    form = LoginForm()
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            user = authenticate(username=form.cleaned_data['username'],
                                password=form.cleaned_data['password'])
            if user and user.is_active:
                login(request, user)
                remote_addr = request.META['REMOTE_ADDR']
                log_admin_action(request, 'logged in')# from ip: %s' % remote_addr)
                config = read_config_file()

                request.session['username'] = form.cleaned_data['username']
                return redirect('blue_mgnt:index')
            else:
                errors = form._errors.setdefault(NON_FIELD_ERRORS , ErrorList())
                errors.append('Invalid username or password')

    return render_to_response('login.html', dict(
        form=form,
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
    return api

def enterprise_required(fun):
    def new_fun(request, *args, **kwargs):
        if not request.session.get('username', False): 
            return redirect('blue_mgnt:login')

        config = read_config_file()
        api = get_api(config)
        account_info = dict()
        quota = api.quota()
        account_info['space_used'] = (quota['bytes_used'] or 0) / (10.0 ** 9)
        account_info['space_allocated'] = (quota['bytes_allocated'] or 0) / (10.0 ** 9)
        account_info['space_available'] = (quota['bytes_available'] or 0) / (10.0 ** 9)
        account_info['show_available'] = True
        if not account_info['space_available']:
            account_info['show_available'] = False
            account_info['space_available'] = account_info['space_allocated']
        account_info['total_users'] = api.get_user_count()
        return fun(request, api, account_info, config, 
                   request.session['username'], *args, **kwargs)
    return new_fun

@enterprise_required
def download_logs(request, api, account_info, config, username):
    date = datetime.datetime.now().strftime('%Y-%m-%d_%H:%M:%S')
    filename = 'openmanage-logs-%s.tar.bz2' % date
    path = '/opt/openmanage/tmp_logs/%s' % filename

    call(['/opt/openmanage/bin/gather_logs.sh', date])

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
    print 'paged'
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

@enterprise_required
def index(request, api, account_info, config, username):
    top_space_used = ['Top 5 Space Used by User',
                      [['larry', 5000],
                       ['bob', 4500],
                       ['sarah', 3800],
                       ['molly', 3000],
                       ['rick', 2200]]]

    top_recent_uploads = ['Top 5 Recent Biggest Uploaders',
                      [['larry', 'image1.jpg'],
                       ['bob', 'doc1.docx'],
                       ['sarah', '.vimrc'],
                       ['molly', 'index.html'],
                       ['rick', 'SomethingElse.js']]]

    top_space_by_group = ['Top 5 Space Use by Group',
                      [['HR', 5000],
                       ['CS', 4500],
                       ['Developers', 3800],
                       ['Testing/QA', 3000],
                       ['Middle Mgnt.', 2200]]]

    top_no_login = ['Top 5 Oldes Not Logged In Accounts',
                      [['Jim', '5/20/2010'],
                       ['Harry', '6/18/2010'],
                       ['Matt', '3/20/2011'],
                       ['Alan', '3/22/2011'],
                       ['Ethan', '1/08/2012']]]

    return render_to_response('index.html', dict(
        username=username,
        features=api.enterprise_features(),
        top_space_used=top_space_used,
        top_recent_uploads=top_recent_uploads,
        top_space_by_group=top_space_by_group,
        top_no_login=top_no_login,
        total_users=3,
        space_used=100,
        space_allocated=300,
        space_available=500,
        account_info=account_info,
    ),
    RequestContext(request))


def process_row(row):
    return dict(name=row['name'],
                plan_id=int(row['plan_id']),
                check_domain=bool(row.get('check_domain', True)),
                webapi_enable=bool(row.get('webapi_enable', True)),
               )

def get_group_form(config, plans, features, show_user_source):
    class GroupForm(forms.Form):
        if config['enable_local_users'] and show_user_source:
            user_source = forms.ChoiceField([('ldap', 'ldap'), ('local', 'local')])
        name = forms.CharField()
        plan_id = forms.ChoiceField(
            [(p['plan_id'], '%s GB' % (p['storage_bytes'] / SIZE_OF_GIGABYTE)) \
             for p in plans],
            label='Plan'
        )
        webapi_enable = forms.BooleanField(required=False, initial=True)
        check_domain = forms.BooleanField(required=False)
        ldap_dn = forms.CharField(required=False, 
                                    widget=forms.Textarea(attrs={'rows':'1', 'cols':'60'}))
        priority = forms.IntegerField(initial=0, required=False)
        group_id = forms.IntegerField(widget=forms.HiddenInput, required=False)
    return GroupForm

@enterprise_required
@permission_required('blue_mgnt.can_view_groups')
def groups(request, api, account_info, config, username, saved=False):
    features = api.enterprise_features()
    plans = api.list_plans()
    groups_list = api.list_groups()
    search = request.GET.get('search', '')
    search_back = request.GET.get('search_back', '')

    if not search:
        search = request.POST.get('search', '')


    class GroupCSVForm(forms.Form):
        csv_file = forms.FileField(label='Group CSV')

        def clean_csv_file(self):
            data = self.cleaned_data['csv_file']

            csv_data = csv.DictReader(data)
            for x, row in enumerate(csv_data):
                try:
                    try:
                        group_id = int(row['group_id'])
                        group = api.get_group(group_id)
                        api.edit_group(group_id, process_row(row))
                    except (KeyError, ValueError), a:
                        api.create_group(process_row(row))
                except Exception, e:
                    raise forms.ValidationError('Invalid data in row %s' % x)
            return data


    class DeleteGroupForm(forms.Form):
        deleted_group_id = forms.ChoiceField([(g['group_id'], g['name']) for g in groups_list],
                                            label='Group to delete')
        new_group_id = forms.ChoiceField([(g['group_id'], g['name']) for g in groups_list],
                                          label='Group to move users to')

        def clean(self):
            cleaned_data = super(DeleteGroupForm, self).clean()
            if cleaned_data.get('deleted_group_id') == cleaned_data.get('new_group_id'):
                raise forms.ValidationError("You must choose a different group to move all users of this group to.")

            return cleaned_data


    class BaseGroupFormSet(forms.formsets.BaseFormSet):
        def clean(self):
            if any(self.errors):
                return
            config_mgr_ = config_mgr.ConfigManager(config_mgr.default_config())
            for x in range(0, self.total_form_count()):
                form = self.forms[x]
                try:
                    group_id = form.cleaned_data['group_id']
                    data = dict(name=form.cleaned_data['name'],
                                plan_id=form.cleaned_data['plan_id'],
                                webapi_enable=form.cleaned_data['webapi_enable'],
                                check_domain=form.cleaned_data.get('check_domain', False),
                                force=('force_plan_change' in self.data),
                                )
                    if group_id:
                        try:
                            log_admin_action(request,
                                             'edit group %s with data: %s' % (group_id, data))
                            api.edit_group(group_id, data)
                        except api.QuotaExceeded:
                            self.show_force = True
                            form._errors['plan_id'] = form.error_class([
                                'Changing the plan of this group will put one '
                                'or more users over quota. Please choose "Force '
                                'Plan Change" if you are sure you want to do this.'])
                    else:
                        log_admin_action(request,
                                         'create group with data: %s' % data)
                        group_id = api.create_group(data)
                    found = False
                    for g in config_mgr_.config['groups']:
                        if g['group_id'] == group_id:
                            g['ldap_id'] = form.cleaned_data['ldap_dn']
                            g['priority'] = form.cleaned_data['priority']
                            found = True
                    if not found:
                        config_mgr_.config['groups'].append(
                            dict(group_id=group_id,
                                    type='dn',
                                    ldap_id=form.cleaned_data['ldap_dn']
                                ))
                except api.DuplicateGroupName:
                    raise forms.ValidationError('Duplicate group name')
            config_mgr_.apply_config()


    GroupForm = get_group_form(config, plans, features, True)
    GroupFormSet = formset_factory(get_group_form(config, plans, features, False),
                                   extra=0, formset=BaseGroupFormSet)

    if search_back == '1':
        search = ''
        initial = groups_list
    elif search:
        initial = api.search_groups(search)
    else:
        initial = groups_list
    
    for i in initial:
        for g in config['groups']:
            if i['group_id'] == g['group_id']:
                i['ldap_dn'] = g['ldap_id']
                i['priority'] = g['priority']
                i['user_source'] = g['user_source']

    groups = GroupFormSet(initial=initial, prefix='groups')
    group_csv = GroupCSVForm()
    new_group = GroupForm()
    delete_group = DeleteGroupForm()
    error = False

    if request.method == 'POST' and request.user.has_perm('blue_mgnt.can_manage_groups'):
        if request.POST.get('form', '') == 'new_group':
            new_group = GroupForm(request.POST)
            if new_group.is_valid():
                data = dict(name=new_group.cleaned_data['name'],
                            plan_id=new_group.cleaned_data['plan_id'],
                            webapi_enable=new_group.cleaned_data['webapi_enable'],
                            check_domain=new_group.cleaned_data.get('check_domain', False),
                           )

                log_admin_action(request, 'create group with data: %s' % data)
                group_id = api.create_group(data)

                config_mgr_ = config_mgr.ConfigManager(config_mgr.default_config())
                data = dict(group_id=group_id,
                            type='dn',
                            ldap_id=new_group.cleaned_data['ldap_dn'],
                            priority=new_group.cleaned_data['priority'],
                            user_source=new_group.cleaned_data.get('user_source', 'ldap')
                           )
                config_mgr_.config['groups'].append(data)
                config_mgr_.apply_config()
                return redirect('blue_mgnt:groups_saved')
        elif request.POST.get('form', '') == 'csv':
            group_csv = GroupCSVForm(request.POST, request.FILES)
            if group_csv.is_valid():
                return redirect('blue_mgnt:groups_saved')
        elif request.POST.get('form', '') == 'delete_group':
            delete_group = DeleteGroupForm(request.POST)
            if delete_group.is_valid():
                deleted_group_id = int(delete_group.cleaned_data['deleted_group_id'])
                new_group_id = int(delete_group.cleaned_data['new_group_id'])
                data = (deleted_group_id, new_group_id)
                log_admin_action(request,
                                 'delete group %s and move users to group %s' % data)
                api.delete_group(deleted_group_id, new_group_id,)
                return redirect('blue_mgnt:groups_saved')
        else:
            if features['group_permissions']:
                groups = GroupFormSet(request.POST, prefix='groups')
                if groups.is_valid():
                    return redirect(reverse('blue_mgnt:groups_saved') + '?search=%s' % search)

    return render_to_response('groups.html', dict(
        initial=initial,
        config=config,
        user=request.user,
        username=username,
        new_group=new_group,
        group_csv=group_csv,
        features=features,
        groups=groups,
        saved=saved,
        error=error,
        account_info=account_info,
        search=search,
        delete_group=delete_group,
        search_back=search_back,
        show_force=getattr(groups, 'show_force', False),
    ),
    RequestContext(request))

@enterprise_required
@permission_required('blue_mgnt.can_manage_shares')
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

# Added shares_detail as a copy of shares() -- benny
@enterprise_required
@permission_required('blue_mgnt.can_manage_shares')
def shares_detail(request, api, account_info, config, username, saved=False):
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

    return render_to_response('shares_detail.html', dict(
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
@permission_required('blue_mgnt.can_manage_settings')
def password(request, api, account_info, config, username, saved=False):
    features = api.enterprise_features()
    password_form = PasswordForm()
    if request.method == 'POST':
        if request.POST.get('form', '') == 'password':
            password_form = PasswordForm(request.POST)
            if password_form.is_valid():
                new_password = password_form.cleaned_data['password']
                log_admin_action(request, 'change password')
                api.update_enterprise_password(new_password)
                config_mgr_ = config_mgr.ConfigManager(config_mgr.default_config())
                config_mgr_.config['api_password'] = new_password
                config_mgr_.apply_config()
                return redirect('blue_mgnt:password_saved')

    return render_to_response('password.html', dict(
        user=request.user,
        username=username,
        features=features,
        password_form=password_form,
        saved=saved,
        account_info=account_info,
    ),
    RequestContext(request))

@enterprise_required
@permission_required('blue_mgnt.can_manage_settings')
def manage(request, api, account_info, config, username):
    return render_to_response('manage.html', dict(
        user=request.user,
        username=username,
        account_info=account_info,
    ),
    RequestContext(request))

