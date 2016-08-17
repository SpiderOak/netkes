import csv

from views import enterprise_required, log_admin_action
from views import SIZE_OF_GIGABYTE
from views import get_config_group

from django import forms
from django.core.urlresolvers import reverse
from django.forms.formsets import formset_factory
from django.template import RequestContext
from django.shortcuts import redirect, render_to_response
from django.contrib.auth.decorators import permission_required
from django.contrib.auth.models import Group, Permission
from django.core.exceptions import ObjectDoesNotExist

from netkes.netkes_agent import config_mgr
from blue_mgnt import models


def get_plan_choices(plans):
    sorted_plans = sorted(plans, key=lambda x: x['storage_bytes'])
    return [(p['plan_id'], '%s GB' % (p['storage_bytes'] / SIZE_OF_GIGABYTE)
            if p['storage_bytes'] / SIZE_OF_GIGABYTE < 1000000001 else 'Unlimited')
            for p in sorted_plans]


def get_policy_choices(policies):
    return [(None, '')] + [(p['id'], p['name']) for p in policies]


def get_group_form(request, config, plans, policies, api, show_user_source=True,
                   new_group=True, ldap_enabled=True):
    class GroupForm(forms.Form):
        name = forms.CharField(label="Group Name", required=True)
        plan_id = forms.ChoiceField(get_plan_choices(plans), label='Plan')
        device_policy = forms.ChoiceField(
            get_policy_choices(policies),
            label='Device Policy',
            required=False,
        )
        webapi_enable = forms.BooleanField(required=False, initial=True)
        check_domain = forms.BooleanField(required=False)
        if ldap_enabled:
            ldap_dn = forms.CharField(required=False,
                                      widget=forms.Textarea(
                                          attrs={'rows': '1', 'cols': '60'}))
            if show_user_source:
                user_source = forms.ChoiceField([('ldap', 'ldap'), ('local', 'local')])
        priority = forms.IntegerField(initial=0, required=False)
        admin_group = forms.BooleanField(required=False)
        permissions = forms.MultipleChoiceField(
                        required=False,
                        choices=[(p.id, p.name) for p in
                                 Permission.objects.filter(
                                     content_type__app_label='blue_mgnt',
                                     content_type__model='AccountsApi'
                                 )],
                        widget=forms.CheckboxSelectMultiple)
        group_id = forms.IntegerField(widget=forms.HiddenInput, required=False)

        if not new_group:
            def clean(self):
                cleaned_data = super(GroupForm, self).clean()
                if 'name' in cleaned_data:
                    device_policy = None
                    if cleaned_data['device_policy']:
                        device_policy = cleaned_data['device_policy']
                    data = dict(
                        name=cleaned_data['name'],
                        plan_id=cleaned_data['plan_id'],
                        device_policy=device_policy,
                        webapi_enable=cleaned_data['webapi_enable'],
                        check_domain=cleaned_data.get('check_domain', False),
                        force=('force_change' in request.POST),
                    )
                    group_id = cleaned_data['group_id']

                    try:
                        api.edit_group(group_id, data)
                        log_admin_action(request,
                                         'edit group %s with data: %s' % (group_id, data))
                        config_mgr_ = config_mgr.ConfigManager(config_mgr.default_config())
                        for g in config_mgr_.config['groups']:
                            if g['group_id'] == group_id:
                                g['ldap_id'] = cleaned_data['ldap_dn']
                                g['priority'] = cleaned_data['priority']
                                g['admin_group'] = cleaned_data['admin_group']
                        config_mgr_.apply_config()

                        django_group, admin_group = get_or_create_admin_group(group_id)
                        django_group.permissions.clear()
                        for permission_id in cleaned_data['permissions']:
                            django_group.permissions.add(Permission.objects.get(pk=permission_id))
                        django_group.save()
                    except api.QuotaExceeded:
                        self.show_force = True
                        msg = ('Changing the plan of this group will put one '
                               'or more users over quota. Please choose "Force '
                               'Plan Change" if you are sure you want to do this.')
                        self._errors['plan_id'] = self.error_class([msg])
                return cleaned_data
    return GroupForm


def add_config_items(group, config):
    g = get_config_group(config, group['group_id'])
    if g:
        group['ldap_dn'] = g['ldap_id']
        group['priority'] = g['priority']
        group['user_source'] = g['user_source']
        group['admin_group'] = g['admin_group']


def process_row(row):
    return dict(
        name=row['name'],
        plan_id=int(row['plan_id']),
        check_domain=bool(row.get('check_domain', True)),
        webapi_enable=bool(row.get('webapi_enable', True)),
    )


@enterprise_required
@permission_required('blue_mgnt.can_view_groups', raise_exception=True)
def groups(request, api, account_info, config, username, saved=False):
    features = api.enterprise_features()
    plans = api.list_plans()
    policies = api.list_policies()
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
                        api.edit_group(group_id, process_row(row))
                    except (KeyError, ValueError):
                        api.create_group(process_row(row))
                except Exception:
                    raise forms.ValidationError('Invalid data in row %s' % x)
            return data

    class BaseGroupFormSet(forms.formsets.BaseFormSet):
        def clean(self):
            if any(self.errors):
                return
            config_mgr_ = config_mgr.ConfigManager(config_mgr.default_config())
            for x in range(0, self.total_form_count()):
                form = self.forms[x]
                try:
                    group_id = form.cleaned_data['group_id']
                    data = dict(
                        name=form.cleaned_data['name'],
                        plan_id=form.cleaned_data['plan_id'],
                        device_policy=form.cleaned_data['device_policy'],
                        webapi_enable=form.cleaned_data['webapi_enable'],
                        check_domain=form.cleaned_data.get('check_domain', False),
                        force=('force_plan_change' in self.data),
                    )
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
                    g = get_config_group(config, group_id)
                    g['ldap_id'] = form.cleaned_data['ldap_dn']
                    g['priority'] = form.cleaned_data['priority']
                except api.DuplicateGroupName:
                    raise forms.ValidationError('Duplicate group name')
            config_mgr_.apply_config()

    GroupForm = get_group_form(request, config, plans, policies, api,
                               ldap_enabled=features['ldap'])
    GroupFormSet = formset_factory(
        get_group_form(request, config, plans, policies, api, False),
        extra=0, formset=BaseGroupFormSet)

    if search_back == '1':
        search = ''
        initial = groups_list
    elif search:
        initial = api.search_groups(search)
    else:
        initial = groups_list

    for i in initial:
        add_config_items(i, config)
        for plan in plans:
            if plan['plan_id'] == i['plan_id']:
                storage_gigs = plan['storage_bytes'] / SIZE_OF_GIGABYTE
                if storage_gigs < 1000000001:
                    i['plan_name'] = '%s GB' % storage_gigs
                else:
                    i['plan_name'] = 'Unlimited'

    groups = GroupFormSet(initial=initial, prefix='groups')
    group_csv = GroupCSVForm()
    new_group = GroupForm()
    error = False

    if request.method == 'POST' and request.user.has_perm('blue_mgnt.can_manage_groups'):
        if request.POST.get('form', '') == 'new_group':
            new_group = GroupForm(request.POST)
            if new_group.is_valid():
                device_policy = None
                if new_group.cleaned_data['device_policy']:
                    device_policy = new_group.cleaned_data['device_policy']
                data = dict(
                    name=new_group.cleaned_data['name'],
                    plan_id=new_group.cleaned_data['plan_id'],
                    device_policy=device_policy,
                    webapi_enable=new_group.cleaned_data['webapi_enable'],
                    check_domain=new_group.cleaned_data.get('check_domain', False),
                )

                log_admin_action(request, 'create group with data: %s' % data)
                group_id = api.create_group(data)

                config_mgr_ = config_mgr.ConfigManager(config_mgr.default_config())
                data = dict(
                    group_id=group_id,
                    type='dn',
                    ldap_id=new_group.cleaned_data.get('ldap_dn', ''),
                    priority=new_group.cleaned_data['priority'],
                    user_source=new_group.cleaned_data.get('user_source', 'local'),
                    admin_group=new_group.cleaned_data['admin_group'],
                )
                config_mgr_.config['groups'].append(data)
                config_mgr_.apply_config()

                django_group, admin_group = get_or_create_admin_group(group_id)
                for permission_id in new_group.cleaned_data['permissions']:
                    django_group.permissions.add(Permission.objects.get(pk=permission_id))
                django_group.save()

                return redirect('blue_mgnt:groups_saved')
        elif request.POST.get('form', '') == 'csv':
            group_csv = GroupCSVForm(request.POST, request.FILES)
            if group_csv.is_valid():
                return redirect('blue_mgnt:groups_saved')
        else:
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
        groups_and_data=zip(groups, initial),
        saved=saved,
        error=error,
        account_info=account_info,
        search=search,
        search_back=search_back,
        show_force=getattr(groups, 'show_force', False),
    ),
        RequestContext(request))


def get_or_create_admin_group(user_group_id):
    try:
        admin_group = models.AdminGroup.objects.get(user_group_id=user_group_id)
        django_group = Group.objects.get(pk=admin_group.group_id)
    except ObjectDoesNotExist:
        django_group = Group.objects.create(name=user_group_id)
        admin_group = models.AdminGroup.objects.create(
            group_id=django_group.id,
            user_group_id=user_group_id)
    return django_group, admin_group


def get_delete_group_form(group_id, config, groups_list):
    group_choices = []
    current_config_group = get_config_group(config, group_id)
    for group in groups_list:
        tmp_group_id = group['group_id']
        tmp_user_source = get_config_group(config, tmp_group_id)['user_source']
        if tmp_group_id != group_id and tmp_user_source == current_config_group['user_source']:
            group_choices.append((group['group_id'], group['name']))

    class DeleteGroupForm(forms.Form):
        new_group_id = forms.ChoiceField(group_choices, label='Group to move users to')

    return DeleteGroupForm


@enterprise_required
@permission_required('blue_mgnt.can_manage_groups', raise_exception=True)
def group_detail(request, api, account_info, config, username, group_id, saved=False):
    group_id = int(group_id)
    plans = api.list_plans()
    policies = api.list_policies()
    groups_list = api.list_groups()
    django_group, admin_group = get_or_create_admin_group(group_id)
    api_group = api.get_group(group_id)
    add_config_items(api_group, config)
    api_group['permissions'] = [p.id for p in django_group.permissions.all()]
    local_group = get_config_group(config, group_id)['user_source'] == 'local'
    fields_not_to_show = []
    if local_group:
        fields_not_to_show = ['ldap_dn', 'priority']

    GroupForm = get_group_form(request, config, plans, policies, api, False, False)
    group_form = GroupForm(data=api_group)
    DeleteGroupForm = get_delete_group_form(group_id, config, groups_list)
    delete_group = DeleteGroupForm()

    if request.method == 'POST':
        if request.POST.get('form', '') == 'delete_group':
            delete_group = DeleteGroupForm(request.POST)
            if delete_group.is_valid():
                new_group_id = int(delete_group.cleaned_data['new_group_id'])
                data = (group_id, new_group_id)
                log_admin_action(request,
                                 'delete group %s and move users to group %s' % data)
                api.delete_group(group_id, new_group_id,)
                config_mgr_ = config_mgr.ConfigManager(config_mgr.default_config())
                for g in config_mgr_.config['groups']:
                    if g['group_id'] == group_id:
                        config_mgr_.config['groups'].remove(g)
                        break
                config_mgr_.apply_config()

                return redirect('blue_mgnt:groups_saved')
        else:
            group_form = GroupForm(request.POST)
            if group_form.is_valid():
                return redirect('blue_mgnt:group_detail_saved', group_id)

    return render_to_response('group_detail.html', dict(
        delete_group=delete_group,
        group_form=group_form,
        group_id=group_id,
        saved=saved,
        fields_not_to_show=fields_not_to_show,
        show_force=getattr(group_form, 'show_force', False),
        account_info=account_info,
    ),
        RequestContext(request))
