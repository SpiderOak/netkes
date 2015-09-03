import datetime
from base64 import b32encode
import csv
import re
from collections import namedtuple
import urllib

from views import enterprise_required, log_admin_action
from views import Pagination
from views import ReadOnlyWidget, get_base_url, SIZE_OF_GIGABYTE
from settings import PasswordForm
from groups import get_config_group

from django import forms
from django.core.urlresolvers import reverse
from django.forms.formsets import formset_factory
from django.template import RequestContext
from django.shortcuts import redirect, render_to_response
from django.utils.safestring import mark_safe

from netkes.account_mgr.user_source import local_source
from blue_mgnt.models import BumpedUser
import openmanage.models as openmanage_models

SIZE_OF_BUMP = 5

new_user_value_re_tests = {
    "avatar": {
        'username': re.compile(r'^[a-zA-Z][a-zA-Z0-9_]{3,37}$'),
    },
}

class UserDetailWidget(ReadOnlyWidget):
    def render(self, name, value, attrs):
        email = super(UserDetailWidget, self).render(name, value, attrs)
        if email:
            link = '<a href="%s">Detail</a>' % (reverse('blue_mgnt:user_detail', args=[email]),)
        else:
            link = ''
        return super(UserDetailWidget, self).render(name, link, attrs)


class LoginLinkWidget(ReadOnlyWidget):
    def render(self, name, value, attrs):
        username = super(LoginLinkWidget, self).render(name, value, attrs)
        b32_username = b32encode(username).rstrip('=')
        link = '<a href="%s/storage/%s/escrowlogin">Login</a>' % (get_base_url(),
                                                                  b32_username,)
        return super(LoginLinkWidget, self).render(name, link, attrs)


class DeleteUserForm(forms.Form):
    orig_email = forms.CharField(widget=forms.HiddenInput)


def get_user_form(local_groups):
    class UserForm(forms.Form):
        group_id = forms.ChoiceField(local_groups, label='Group')
        orig_email = forms.CharField(widget=forms.HiddenInput)
    return UserForm


def get_base_user_form_set(api, request):
    class BaseUserFormSet(forms.formsets.BaseFormSet):
        def clean(self):
            if any(self.errors):
                return
            for x in range(0, self.total_form_count()):
                form = self.forms[x]
                data = dict(group_id=form.cleaned_data['group_id'], )
                if request.user.has_perm('blue_mgnt.can_manage_users'):
                    log_admin_action(request,
                                    'edit user %s ' % form.cleaned_data['orig_email'] + \
                                    'with data: %s' % data)
                    api.edit_user(form.cleaned_data['orig_email'], data)
    return BaseUserFormSet

def get_user_csv_form(api):
    class UserCSVForm(forms.Form):
        csv_file = forms.FileField(label='User CSV')

        def clean_csv_file(self):
            data = self.cleaned_data['csv_file']

            csv_data = csv.DictReader(data)
            for x, row in enumerate(csv_data):
                if not('email' in row):
                    raise forms.ValidationError('Invalid data in row %s. email is required' % x)
                if row.get('name'):
                    if not new_user_value_re_tests['avatar']['firstname'].match(row['name']):
                        raise forms.ValidationError('Invalid data in row %s. Names must be between 1 and 45 characters long' % x)
                    name = row['name']
                if row.get('new_email'):
                    if not new_user_value_re_tests['avatar']['email'].match(row['new_email']):
                        raise forms.ValidationError('Invalid data in row %s. Invalid new_email' % x)

                user_info = dict()
                if row.get('new_email'):
                    user_info['email'] = row['new_email']
                if row.get('name'):
                    user_info['name'] = row['name']
                if row.get('group_id'):
                    user_info['group_id'] = row['group_id']
                if row.get('enabled'):
                    user_info['enabled'] = row['enabled']
                try:
                    log_admin_action(request,
                                     'edit user %s through csv. ' % row['email'] + \
                                     'set user data to: %s' % user_info
                                    )
                    api.edit_user(row['email'], user_info)
                except Api.NotFound:
                    raise forms.ValidationError('Invalid data in row %s. email not found' % x)
            return data
    return UserCSVForm

def get_plan_id(groups, group_id):
    return [x for x in groups if \
            x['group_id'] == int(group_id)][0]['plan_id']

def get_group(groups, group_name):
    for group in groups:
        if group['name'].lower() == group_name.lower():
            return group

def create_user(api, account_info, config, data):
    email = data['email']
    api.create_user(data)
    # Set a blank password so that the password can be set
    # through the set password email.
    local_source.set_user_password(local_source._get_db_conn(config),
                                   email, '')
    if config['send_activation_email']:
        api.send_activation_email(email, dict(template_name='set_password'))

def _csv_create_users(api, account_info, groups, config, request, csv_data):
    for x, row in enumerate(csv_data):
        group = get_group(groups, row['group_name'])
        if not group:
            msg = 'Invalid data in row %s. Invalid Group' % x
            return x, forms.ValidationError(msg)
        group_id = group['group_id']
        config_group = get_config_group(config, group_id)
        if config_group['user_source'] != 'local':
            msg = 'Invalid data in row %s.' % x
            return x, forms.ValidationError(msg + ' group_name must be a local group')
        plan_id = get_plan_id(groups, group_id)
        user_info = dict(
            email=row['email'],
            name=row['name'],
            group_id=group_id,
            plan_id=plan_id,
        )
        try:
            create_user(api, account_info, config, user_info)
            log_admin_action(request, 'create user through csv: %s' % user_info)
        except api.DuplicateEmail:
            msg = 'Invalid data in row %s. Email already in use' % x
            return x, forms.ValidationError(msg)
        except api.PaymentRequired:
            msg = ('Payment required. '
                    'Please update your <a href="/billing/">billing</a> '
                    'information to unlock your account.')
            return x, forms.ValidationError(mark_safe(msg))
        except api.DuplicateUsername:
            msg = 'Invalid data in row %s. Username already in use' % x
            return x, forms.ValidationError(msg)
    return x + 1, None

def get_new_user_csv_form(api, groups, account_info, config, request):
    class UserCSVForm(forms.Form):
        csv_file = forms.FileField(label='User CSV')

        def clean_csv_file(self):
            data = self.cleaned_data['csv_file']

            csv_data = csv.DictReader(data)
            for x, row in enumerate(csv_data):
                msg = 'Invalid data in row %s.' % x
                if 'email' not in row:
                    raise forms.ValidationError(msg + ' email is required')
                if '@' not in row['email']:
                    raise forms.ValidationError(msg + ' invalid email')
                if 'name' not in row:
                    raise forms.ValidationError(msg + ' name is required')
                if 'group_name' not in row:
                    raise forms.ValidationError(msg + ' group_name is required')

            csv_data = csv.DictReader(data)
            msg = False
            created, e = _csv_create_users(api, account_info, groups,
                                           config, request, csv_data)
            if e is not None:
                raise e
            return data
    return UserCSVForm

def get_new_user_form(api, features, account_info, config, local_groups, groups, request):
    class NewUserForm(forms.Form):
        if not features['email_as_username']:
            username = forms.CharField(max_length=45)
        email = forms.EmailField()
        name = forms.CharField(max_length=45)
        group_id = forms.ChoiceField(local_groups, label='Group')

        def clean_username(self):
            data = self.cleaned_data['username']
            if not new_user_value_re_tests['avatar']['username'].match(data):
                raise forms.ValidationError('Your username must start with a letter, '
                                            'be at least four characters long, '
                                            'and may contain letters, numbers, '
                                            'and underscores.')
            return data

        def clean(self):
            cleaned_data = super(NewUserForm, self).clean()
            email = cleaned_data.get('email', '')
            name = cleaned_data.get('name', '')
            group_id = cleaned_data['group_id']
            username = cleaned_data.get('username', '')

            valid_username = username
            if not hasattr(self, username):
                valid_username = True

            if email and name and group_id and valid_username:
                plan_id = get_plan_id(groups, group_id)
                data = dict(email=email, name=name, group_id=group_id, plan_id=plan_id)
                if username:
                    data.update(dict(username=username))
                try:
                    create_user(api, account_info, config, data)
                    log_admin_action(request, 'create user: %s' % data)
                except api.DuplicateEmail:
                    self._errors['email'] = self.error_class(["Email address already in use"])
                except api.PaymentRequired:
                    msg = ('Payment required. '
                           'Please update your <a href="/billing/">billing</a> '
                           'information to unlock your account.')
                    raise forms.ValidationError(mark_safe(msg))
                except api.DuplicateUsername:
                    self._errors['username'] = self.error_class(["Username already in use"])

            return cleaned_data
    return NewUserForm

def get_group_name(groups, group_id):
    for group in groups:
        if group['group_id'] == group_id:
            return group['name']

def get_plan_name(plans, plan_id):
    for plan in plans:
        if plan['plan_id'] == plan_id:
            storage_gigs = plan['storage_bytes'] / SIZE_OF_GIGABYTE
            if storage_gigs < 1000000001:
                return '%s GB' % storage_gigs
            else:
                return 'Unlimited'

def get_local_groups(config, groups):
    local_groups = []
    for c_group in config['groups']:
        if c_group['user_source'] == 'local':
            for api_group in groups:
                if c_group['group_id'] == api_group['group_id']:
                    local_groups.append((c_group['group_id'], api_group['name']))
    return local_groups

def is_local_user(config, group_id):
    for group in config['groups']:
        if group['group_id'] == group_id:
            return group['user_source'] == 'local'
    return False

def get_login_link(username):
    return reverse('blue_mgnt:escrow_login', args=[username])

class UserColumn(object):
    def __init__(self, name, header, type_):
        self.name = name
        self.header = header
        self.type = type_

USER_COLUMNS = [
    UserColumn('username', 'Username', 'text'),
    UserColumn('name', 'Name', 'text'),
    UserColumn('email', 'Email', 'email'),
    UserColumn('share_id', 'Share ID', 'text'),
    UserColumn('promo', 'Promo', 'text'),
    UserColumn('creation_time', 'Creation Time', 'timestamp'),
    UserColumn('last_login', 'Last Login', 'timestamp'),
    UserColumn('bytes_stored', 'Storage Size', 'bytes'),
    UserColumn('storage_bytes', 'Max Storage Size', 'bytes'),
    UserColumn('bonus_bytes', 'Bonus GB', 'bytes'),
    UserColumn('plan_id', 'Plan', 'plan'),
    UserColumn('group_id', 'Group', 'group'),
    UserColumn('enabled', 'Enabled', 'text'),
    UserColumn('purgehold_active', 'Purgehold Active', 'text'),
]

def get_user_columns(columns):
    user_columns = []
    for column in columns:
        found = False
        for user_column in USER_COLUMNS:
            if column == user_column.name:
                user_columns.append(user_column)
                found = True
        if not found:
            return user_columns, '"%s" is not a valid column' % column
    return user_columns, False

def get_user_rows(all_users, delete_user_formset, user_formset,
                  config, user_columns, groups):
    index = 0
    for user, delete in zip(all_users, delete_user_formset):
        user_row = {
            'selected_columns': [],
            'email': user['email'],
            'is_local_user': is_local_user(config, user['group_id']),
            'delete_form': delete,
            'enabled': user['enabled']
        }
        for column in user_columns:
            if column.name == 'group_id':
                if user_row['is_local_user']:
                    user_row['form'] = user_formset[index]
                    index += 1

            value = user[column.name]
            if column.type == 'timestamp':
                value = datetime.datetime.fromtimestamp(value) if value else None
            if column.type == 'group':
                value = get_group_name(groups, value)
            user_row['selected_columns'].append((value, column.type))
        yield user_row

@enterprise_required
def users(request, api, account_info, config, username, saved=False):
    show_disabled = int(request.GET.get('show_disabled', 1))
    groups = api.list_groups()
    plans = api.list_plans()
    features = api.enterprise_features()
    search = request.GET.get('search', '')
    local_groups = get_local_groups(config, groups)
    user_count = api.get_user_count()
    page = int(request.GET.get('page', 1))
    pagination = Pagination('blue_mgnt:users',
                            user_count,
                            page,
                           )
    order_by = request.GET.get('order_by', '')
    search_by = urllib.unquote(request.GET.get('search_by', ''))
    all_user_columns = USER_COLUMNS

    if features['email_as_username']:
        default_columns = 'name,email,group_id,bytes_stored'
    else:
        default_columns = 'username,name,email,group_id,bytes_stored'
    column_arg = request.GET.getlist('columns', default_columns)
    if type(column_arg) is list:
        column_arg = ','.join(map(str, column_arg))
    columns = [x.strip() for x in column_arg.split(',')]
    user_columns, error = get_user_columns(columns)
    for column in user_columns:
        if column.name == order_by:
            column.order_by = '-%s' % column.name
        else:
            column.order_by = column.name

    UserCSVForm = get_new_user_csv_form(api, groups, account_info, config, request)
    NewUserForm = get_new_user_form(api, features, account_info,
                                    config, local_groups, groups, request)
    BaseUserFormSet = get_base_user_form_set(api, request)
    UserForm = get_user_form(local_groups)
    UserFormSet = formset_factory(UserForm, extra=0, formset=BaseUserFormSet)
    DeleteUserFormSet = formset_factory(DeleteUserForm, extra=0, can_delete=True)

    if search:
        all_users = api.search_users(search, pagination.per_page, pagination.query_offset)
    else:
        all_users = api.list_users(pagination.per_page,
                                   pagination.query_offset,
                                   order_by=order_by,
                                   search_by=search_by,
                                  )

    if len(all_users) < pagination.per_page:
        pagination = Pagination('blue_mgnt:users',
                                page * pagination.per_page,
                                page,
                               )

    if not show_disabled:
        all_users = [x for x in all_users if x['enabled']]

    users = [dict(orig_email=x['email'],
                  group_id=x['group_id'],
                  is_local_user=is_local_user(config, x['group_id']),
                 ) for x in all_users]
    local_users = [user for user in users if user['is_local_user']]

    user_formset = UserFormSet(initial=local_users, prefix='tmp_user')
    delete_user_formset = DeleteUserFormSet(initial=users, prefix='delete_user')
    user_csv = UserCSVForm()
    new_user = NewUserForm()

    # Use the name instead of the ID
    for row in all_users:
        row['plan_id'] = get_plan_name(plans, row['plan_id'])

    user_rows = get_user_rows(all_users, delete_user_formset,
                              user_formset, config,
                              user_columns, groups
                             )

    get_args = urllib.urlencode(dict(
        search=search,
        order_by=order_by,
        search_by=search_by,
        columns=column_arg
    ))

    class UserColumnsForm(forms.Form):
        columns = forms.MultipleChoiceField(required=False,
                choices=[(item.name, item.header) for item in USER_COLUMNS],
                widget=forms.CheckboxSelectMultiple)

    column_form = UserColumnsForm(initial={'columns': columns})

    if request.method == 'POST':
        if request.POST.get('form', '') == 'csv':
            user_csv = UserCSVForm(request.POST, request.FILES)
            if user_csv.is_valid():
                return redirect('blue_mgnt:users_saved')
        elif request.POST.get('form', '') == 'new_user':
            new_user = NewUserForm(request.POST)
            if new_user.is_valid():
                return redirect('blue_mgnt:users_saved')
        else:
            user_formset = UserFormSet(request.POST, prefix='tmp_user')
            delete_user_formset = DeleteUserFormSet(request.POST, prefix='delete_user')
            if (request.user.has_perm('blue_mgnt.can_manage_users')
                and user_formset.is_valid()
                and delete_user_formset.is_valid()):
                for form in delete_user_formset.deleted_forms:
                    orig_email = form.cleaned_data['orig_email']
                    api.delete_user(orig_email)
                    log_admin_action(request, 'delete user "%s"' % orig_email)
                return redirect(reverse('blue_mgnt:users_saved') + '?search=%s' % search)

    return render_to_response('users.html', dict(
        order_by=order_by,
        search_by=search_by,
        columns=column_arg,
        get_args=get_args,
        error=error,
        user_columns=user_columns,
        user=request.user,
        config=config,
        new_user=new_user,
        username=username,
        user_formset=user_formset,
        delete_user_formset=delete_user_formset,
        user_csv=user_csv,
        features=features,
        saved=saved,
        account_info=account_info,
        show_disabled=show_disabled,
        search=search,
        user_rows=user_rows,
        pagination=pagination,
        all_user_columns=all_user_columns,
        column_form=column_form,
    ),
    RequestContext(request))

@enterprise_required
def user_detail(request, api, account_info, config, username, email, saved=False):
    user = api.get_user(email)
    devices = api.list_devices(email)
    if devices:
        user['last_backup_complete'] = max(x['last_backup_complete'] for x in devices)
    else:
        user['last_backup_complete'] = None
    features = api.enterprise_features()
    local_user = is_local_user(config, user['group_id'])
    groups = api.list_groups()
    local_groups = get_local_groups(config, groups)

    reset_password_message = ''
    pw = openmanage_models.Password.objects.filter(email=email)
    if local_user:
        if pw and pw[0].pw_hash:
            reset_password_message = 'Send Password Reset Email'
        else:
            reset_password_message = 'Resend Welcome Email'

    class UserForm(forms.Form):
        if local_user:
            name = forms.CharField(max_length=45)
            email = forms.EmailField()
            group_id = forms.ChoiceField(local_groups, label='Group')
            enabled = forms.BooleanField(required=False)
        else:
            name = forms.CharField(widget=ReadOnlyWidget, required=False, max_length=45)
            email = forms.EmailField(widget=ReadOnlyWidget, required=False)
            group_id = forms.ChoiceField(
                local_groups,
                label='Group',
                widget=ReadOnlyWidget, required=False
            )
            enabled = forms.BooleanField(widget=ReadOnlyWidget, required=False)
        bonus_gigs = forms.IntegerField(
            label="Bonus GBs",
            help_text='Add extra space for this specific user.'
        )
        purgehold_active = forms.BooleanField(
            label="Purgehold Active",
            help_text="If set deleted data will not be purged from the system.",\
            required=False,
        )

        def clean_email(self):
            new_email = self.cleaned_data['email']
            if new_email and new_email != email:
                try:
                    api.get_user(new_email)
                    raise forms.ValidationError('A user with this email already exists')
                except api.NotFound:
                    pass

            return new_email

        def save(self):
            user_data = dict()
            user_data['purgehold_active'] = self.cleaned_data['purgehold_active']
            if local_user:
                user_data.update(self.cleaned_data)
                del user_data['bonus_gigs']
                if email != user_data['email']:
                    try:
                        password = openmanage_models.Password.objects.get(email=email)
                        password.update_email(user_data['email'])
                    except openmanage_models.Password.DoesNotExist:
                        pass
            if request.user.has_perm('blue_mgnt.can_edit_bonus_gigs'):
                user_data['bonus_bytes'] = user_form.cleaned_data['bonus_gigs'] * SIZE_OF_GIGABYTE
            if user_data:
                log_admin_action(request, 'edit user "%s" with data: %s' % (email, user_data))
                api.edit_user(email, user_data)

    data = dict()
    data.update(user)
    data['bonus_gigs'] = user['bonus_bytes'] / SIZE_OF_GIGABYTE
    if not local_user:
        data['group_id'] = get_group_name(groups, data['group_id'])
    user_form = UserForm(initial=data)
    password_form = PasswordForm()
    if request.method == 'POST':
        if request.POST.get('form', '') == 'edit_user':
            user_form = UserForm(request.POST)
            if request.user.has_perm('blue_mgnt.can_manage_users') and user_form.is_valid():
                user_form.save()
                return redirect('blue_mgnt:user_detail_saved',
                                user_form.cleaned_data.get('email') or email)
        if request.POST.get('form', '') == 'reset_password':
            if request.user.has_perm('blue_mgnt.can_manage_users'):
                local_source.set_user_password(local_source._get_db_conn(config),
                                               email, '')
                api.send_activation_email(email, dict(template_name='set_password',
                                                      reg_code='not used'
                                                     ))
                return redirect('blue_mgnt:user_detail_saved', email)
        if request.POST.get('form', '') == 'password':
            password_form = PasswordForm(request.POST)
            if password_form.is_valid():
                log_admin_action(request, 'change password for: %s' % email)
                password = password_form.cleaned_data['password'].encode('utf-8')
                local_source.set_user_password(local_source._get_db_conn(config),
                                                email, password)
                return redirect('blue_mgnt:user_detail_saved', data.get('email', email))
        if request.POST.get('form', '') == 'delete_user':
            if request.user.has_perm('blue_mgnt.can_manage_users'):
                log_admin_action(request, 'delete user %s' % email)
                api.delete_user(email)
                return redirect('blue_mgnt:users')
        if request.POST.get('form', '') == 'bump_space':
            if request.user.has_perm('blue_mgnt.can_edit_bonus_gigs'):
                log_admin_action(request, 'bump space for user %s' % email)
                data = {
                    'bonus_bytes': (data['bonus_gigs'] + SIZE_OF_BUMP) * SIZE_OF_GIGABYTE
                }
                api.edit_user(email, data)
                time_to_reset = datetime.datetime.now() + datetime.timedelta(days=3)
                BumpedUser.objects.create(email=email,
                                          time_to_reset_bonus_gb=time_to_reset)
                return redirect('blue_mgnt:user_detail_saved', data.get('email', email))
        if request.POST.get('form', '') == 'edit_share':
            room_key = request.POST['room_key']
            enable = request.POST['enabled'] == 'False'
            msg = 'edit share %s for user %s. Action %s share' % \
                    (room_key, email, 'enable' if enable else 'disable')
            log_admin_action(request, msg)
            api.edit_share(email, room_key, enable)
            return redirect('blue_mgnt:user_detail_saved', email)

    return render_to_response('user_detail.html', dict(
        shares=api.list_shares(email),
        share_url=get_base_url(),
        username=username,
        local_user=local_user,
        email=email,
        api_user=user,
        storage_login=get_login_link(data['username']),
        user_form=user_form,
        password_form=password_form,
        features=features,
        account_info=account_info,
        reset_password_message=reset_password_message,
        datetime=datetime,
        devices=devices,
        saved=saved,
    ),
    RequestContext(request))
