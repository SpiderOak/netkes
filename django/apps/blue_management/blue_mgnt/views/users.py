import datetime
from base64 import b32encode
import csv

from views import enterprise_required, render_to_response, log_admin_action
from views import ReadOnlyWidget, get_base_url, SIZE_OF_GIGABYTE
from views import pageit
from groups import get_config_group

from django import forms
from django.core.urlresolvers import reverse
from django.forms.formsets import formset_factory
from django.template import RequestContext
from django.shortcuts import redirect

from netkes.account_mgr.user_source import local_source

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
        group_id = forms.ChoiceField(local_groups)
        orig_email = forms.CharField(widget=forms.HiddenInput)
    return UserForm

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

def get_new_user_csv_form(api, groups, config, request):
    class UserCSVForm(forms.Form):
        csv_file = forms.FileField(label='User CSV')

        def clean_csv_file(self):
            data = self.cleaned_data['csv_file']

            csv_data = csv.DictReader(data)
            for x, row in enumerate(csv_data):
                msg = 'Invalid data in row %s.' % x
                if 'email' not in row:
                    raise forms.ValidationError(msg + ' email is required')
                if 'name' not in row:
                    raise forms.ValidationError(msg + ' name is required')
                if 'password' not in row:
                    raise forms.ValidationError(msg + ' password is required')
                if 'group_name' not in row:
                    raise forms.ValidationError(msg + ' group_name is required')

            csv_data = csv.DictReader(data)
            for x, row in enumerate(csv_data):
                group = get_group(groups, row['group_name'])
                group_id = group['group_id']
                config_group = get_config_group(config, group_id)
                if config_group['user_source'] != 'local':
                    msg = 'Invalid data in row %s.' % x
                    raise forms.ValidationError(msg + ' group_name must be a local group')
                plan_id = get_plan_id(groups, group_id) 
                user_info = dict(
                    email=row['email'],
                    name=row['name'],
                    group_id=group_id,
                    plan_id=plan_id,
                )
                try:
                    api.create_user(user_info)
                    local_source.set_user_password(local_source._get_db_conn(config),
                                                   row['email'], row['password'])
                    log_admin_action(request, 'create user through csv: %s' % user_info)
                except api.DuplicateEmail:
                    msg = 'Invalid data in row %s. Email already in use' % x
                    raise forms.ValidationError(msg)
            return data
    return UserCSVForm

def get_new_user_form(api, features, config, local_groups, groups, request):
    class NewUserForm(forms.Form):
        if not features['email_as_username']:
            username = forms.CharField(max_length=45)
        email = forms.EmailField()
        name = forms.CharField(max_length=45)
        password = forms.CharField(max_length=64, widget=forms.PasswordInput)
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
            password = cleaned_data.get('password', '')

            valid_username = username
            if not hasattr(self, username):
                valid_username = True

            if email and name and group_id and valid_username:
                plan_id = get_plan_id(groups, group_id) 
                data = dict(email=email, name=name, group_id=group_id, plan_id=plan_id)
                if username:
                    data.update(dict(username=username))
                try:
                    api.create_user(data)
                    local_source.set_user_password(local_source._get_db_conn(config),
                                                   email, password)
                    log_admin_action(request, 'create user: %s' % data)
                except api.DuplicateEmail:
                    self._errors['email'] = self.error_class(["Email address already in use"])
                except api.DuplicateUsername:
                    self._errors['username'] = self.error_class(["Username already in use"])

            return cleaned_data
    return NewUserForm

def get_group_name(groups, group_id):
    for group in groups:
        if group['group_id'] == group_id:
            return group['name']

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

@enterprise_required
def users(request, api, account_info, config, username, saved=False):
    page = int(request.GET.get('page', 1))
    show_disabled = int(request.GET.get('show_disabled', 1))
    search_back = request.GET.get('search_back', '')
    groups = api.list_groups()
    features = api.enterprise_features()
    search = request.GET.get('search', '')
    local_groups = get_local_groups(config, groups)
    all_pages=pageit('users', api, page, None)
    if not search:
        search = request.POST.get('search', '')

    UserCSVForm = get_new_user_csv_form(api, groups, config, request)
    NewUserForm = get_new_user_form(api, features, config, local_groups, groups, request)

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


    TmpUserForm = get_user_form(local_groups)
    TmpUserFormSet = formset_factory(TmpUserForm, extra=0, formset=BaseUserFormSet)
    DeleteUserFormSet = formset_factory(DeleteUserForm, extra=0, can_delete=True)
    page = int(page)
    user_limit = 25
    user_offset = user_limit * (page - 1)
    if search_back == '1':
        search = ''
        all_users = api.list_users(user_limit, user_offset)
    elif search:
        all_users = api.search_users(search, user_limit, user_offset)
    else:
        all_users = api.list_users(user_limit, user_offset)

    next_page = len(all_users) == user_limit

    all_users.sort(key=lambda x: x['creation_time'], reverse=True)

    if not show_disabled:
        all_users = [x for x in all_users if x['enabled']]
    page_users = all_users

    initial = []
    for x in page_users:
        entry = dict(username=x['username'],
                     email=x['email'],
                     orig_email=x['email'],
                     user_detail=x['email'],
                     name=x['name'],
                     bytes_stored=x['bytes_stored'],
                     #gigs_stored=round(x['bytes_stored'] / (10.0 ** 9), 2),
                     creation_time=datetime.datetime.fromtimestamp(x['creation_time']),
                     last_login=datetime.datetime.fromtimestamp(x['last_login']) if x['last_login'] else None,
                     group_id=x['group_id'] if 'group_id' in x else '',
                     escrow_login=x['username'],
                     enabled=x['enabled'],
                     login_link=get_login_link(x['username']),
                     is_local_user=is_local_user(config, x['group_id']),
                     group_name=get_group_name(groups, x['group_id']),
                    )
        initial.append(entry)
    local_users = []
    for user_row in initial:
        if user_row['is_local_user']:
            local_users.append(user_row)
    for x, local_user in enumerate(local_users):
        local_user['index'] = x

    tmp_user_formset = TmpUserFormSet(initial=local_users, prefix='tmp_user')
    delete_user_formset = DeleteUserFormSet(initial=initial, prefix='delete_user')
    user_csv = UserCSVForm()
    new_user = NewUserForm()

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
            tmp_user_formset = TmpUserFormSet(request.POST, prefix='tmp_user')
            delete_user_formset = DeleteUserFormSet(request.POST, prefix='delete_user')
            if (request.user.has_perm('blue_mgnt.can_manage_users')
                and tmp_user_formset.is_valid()
                and delete_user_formset.is_valid()):
                for form in delete_user_formset.deleted_forms:
                    orig_email = form.cleaned_data['orig_email']
                    api.delete_user(orig_email)
                    log_admin_action(request, 'delete user "%s"' % orig_email)
                return redirect(reverse('blue_mgnt:users_saved') + '?search=%s' % search)

    index = 0
    for user in initial:
        if user['is_local_user']:
            user['form'] = tmp_user_formset[index]
            index += 1

    return render_to_response('index.html', dict(
        all_users=initial,
        user=request.user,
        page=page,
        config=config,
        next_page=next_page,
        new_user=new_user,
        username=username,
        tmp_user_formset=tmp_user_formset,
        delete_user_formset=delete_user_formset,
        user_csv=user_csv,
        features=api.enterprise_features(),
        page_users=page_users,
        saved=saved,
        account_info=account_info,
        show_disabled=show_disabled,
        search=search,
        search_back=search_back,
        users_and_delete=zip(initial, delete_user_formset),
        all_pages=all_pages,
    ),
    RequestContext(request))

@enterprise_required
def user_detail(request, api, account_info, config, username, email, saved=False):
    user = api.get_user(email)
    devices = api.list_devices(email)
    features = api.enterprise_features()
    local_user = is_local_user(config, user['group_id'])
    local_groups = get_local_groups(config, api.list_groups())

    class UserForm(forms.Form):
        if local_user:
            name = forms.CharField(max_length=45)
            email = forms.EmailField()
            group_id = forms.ChoiceField(local_groups, label='Group ID')
            password = forms.CharField(max_length=64, 
                                       widget=forms.PasswordInput,
                                       required=False
                                      )
            enabled = forms.BooleanField(required=False)
        else:
            name = forms.CharField(widget=ReadOnlyWidget, required=False, max_length=45)
            email = forms.EmailField(widget=ReadOnlyWidget, required=False)
            group_id = forms.ChoiceField(
                local_groups,
                label='Group ID',
                widget=ReadOnlyWidget, required=False
            )
            enabled = forms.BooleanField(widget=ReadOnlyWidget, required=False)
        bonus_gigs = forms.IntegerField(label="Bonus GBs", min_value=0)

    data = dict()
    data.update(user)
    data['bonus_gigs'] = user['bonus_bytes'] / SIZE_OF_GIGABYTE
    user_form = UserForm(initial=data)
    if request.method == 'POST':
        if request.POST.get('form', '') == 'resend_email':
            log_admin_action(request, 'resent activation email for %s ' % email)
            api.send_activation_email(email)
            return redirect('blue_mgnt:user_detail', email)
        if request.POST.get('form', '') == 'edit_user':
            user_form = UserForm(request.POST)
            if request.user.has_perm('blue_mgnt.can_manage_users') and user_form.is_valid():
                data = dict()
                if local_user:
                    data.update(user_form.cleaned_data)
                    del data['bonus_gigs']
                if 'password' in data:
                    if data['password']:
                        local_source.set_user_password(local_source._get_db_conn(config),
                                                    email, data['password'])
                    del data['password']
                if request.user.has_perm('blue_mgnt.can_edit_bonus_gigs'):
                    data['bonus_bytes'] = user_form.cleaned_data['bonus_gigs'] * SIZE_OF_GIGABYTE
                if data:
                    log_admin_action(request, 'edit user "%s" with data: %s' % (email, data))
                    api.edit_user(email, data)
                return redirect('blue_mgnt:user_detail_saved', data.get('email', email))
        if request.POST.get('form', '') == 'delete_user':
            if request.user.has_perm('blue_mgnt.can_manage_users'):
                api.delete_user(email)
                return redirect('blue_mgnt:users')
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
        email=email,
        api_user=user,
        storage_login=get_login_link(data['username']),
        user_form=user_form,
        features=features,
        account_info=account_info,
        datetime=datetime,
        devices=devices,
        saved=saved,
    ),
    RequestContext(request))
