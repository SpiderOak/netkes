from views import enterprise_required, render_to_response, log_admin_action
from views import ReadOnlyWidget, get_base_url, SIZE_OF_GIGABYTE

from django import forms
from django.core.urlresolvers import reverse
from django.forms.formsets import formset_factory
from django.template import RequestContext
from django.shortcuts import redirect
from django.contrib.auth.decorators import permission_required
from django.contrib.auth.models import Group, Permission
from django.core.exceptions import ObjectDoesNotExist

from netkes.account_mgr.user_source import local_source
from netkes.netkes_agent import config_mgr
from blue_mgnt import models

def get_group_form(request, config, plans, show_user_source):
    class GroupForm(forms.Form):
        name = forms.CharField(label="Group Name")
        plan_id = forms.ChoiceField(
            [(p['plan_id'], '%s GB' % (p['storage_bytes'] / SIZE_OF_GIGABYTE)) \
             for p in plans],
            label='Plan'
        )
        webapi_enable = forms.BooleanField(required=False, initial=True)
        check_domain = forms.BooleanField(required=False)
        ldap_dn = forms.CharField(required=False,
                                    widget=forms.Textarea(attrs={'rows':'1', 'cols':'60'}))
        if config['enable_local_users'] and show_user_source:
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
    return GroupForm

def get_config_group(config, group_id):
    for group in config['groups']:
        if group['group_id'] == group_id:
            return group

def add_config_items(group, config):
    g = get_config_group(config, group['group_id'])
    group['ldap_dn'] = g['ldap_id']
    group['priority'] = g['priority']
    group['user_source'] = g['user_source']
    group['admin_group'] = g['admin_group']

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


    GroupForm = get_group_form(request, config, plans, True)
    GroupFormSet = formset_factory(get_group_form(request, config, plans, False),
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

    groups = GroupFormSet(initial=initial, prefix='groups')
    group_csv = GroupCSVForm()
    new_group = GroupForm()
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
                            user_source=new_group.cleaned_data.get('user_source', 'ldap'),
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
@permission_required('blue_mgnt.can_manage_groups')
def group_detail(request, api, account_info, config, username, group_id, saved=False):
    group_id = int(group_id)
    plans = api.list_plans()
    groups_list = api.list_groups()
    GroupForm = get_group_form(request, config, plans, False)
    django_group, admin_group = get_or_create_admin_group(group_id)
    api_group = api.get_group(group_id)
    add_config_items(api_group, config)
    api_group['permissions'] = [p.id for p in django_group.permissions.all()]
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
                return redirect('blue_mgnt:groups_saved')
        else:
            group_form = GroupForm(request.POST)
            if group_form.is_valid():
                data = dict(name=group_form.cleaned_data['name'],
                            plan_id=group_form.cleaned_data['plan_id'],
                            webapi_enable=group_form.cleaned_data['webapi_enable'],
                            check_domain=group_form.cleaned_data.get('check_domain', False),
                            )

                log_admin_action(request, 'edit group with data: %s' % data)
                api.edit_group(group_id, data)

                config_mgr_ = config_mgr.ConfigManager(config_mgr.default_config())
                for g in config_mgr_.config['groups']:
                    if g['group_id'] == group_id:
                        g['ldap_id'] = group_form.cleaned_data['ldap_dn']
                        g['priority'] = group_form.cleaned_data['priority']
                        g['admin_group'] = group_form.cleaned_data['admin_group']
                config_mgr_.apply_config()

                django_group, admin_group = get_or_create_admin_group(group_id)
                django_group.permissions.clear()
                for permission_id in group_form.cleaned_data['permissions']:
                    django_group.permissions.add(Permission.objects.get(pk=permission_id))
                django_group.save()
                return redirect('blue_mgnt:group_detail', group_id)

    return render_to_response('group_detail.html', dict(
        delete_group=delete_group,
        group_form=group_form,
        group_id=group_id,
    ),
    RequestContext(request))


@enterprise_required
@permission_required('blue_mgnt.can_manage_admins')
def admin_groups(request, api, account_info, config, username, saved=False):
    features = api.enterprise_features()
    groups_list = api.list_groups()

    class AdminGroupForm(forms.Form):
        name = forms.CharField()
        #ldap_dn = forms.CharField(required=True, 
        #                          widget=forms.Textarea(attrs={'rows':'1', 'cols':'60'}))
        user_group_id = forms.ChoiceField([(g['group_id'], g['name']) for g in groups_list],
                                          label='Group')
        permissions = forms.MultipleChoiceField(
                        required=False,
                        choices=[(p.id, p.name) for p in
                                 request.user.user_permissions.all()],
                        widget=forms.CheckboxSelectMultiple)
        group_id = forms.IntegerField(widget=forms.HiddenInput, required=False)

        def clean(self):
            cleaned_data = super(AdminGroupForm, self).clean()
            name = cleaned_data.get('name', '')
            group_id = cleaned_data.get('group_id', '')

            try:
                group = Group.objects.get(name=name)
                if group.id != group_id:
                    self._errors['name'] = self.error_class(["There is already a group with this name"])
            except Group.DoesNotExist:
                pass

            return cleaned_data


    initial = []
    for group in Group.objects.all():
        admin_group = models.AdminGroup.objects.get(pk=group.id)
        initial.append(dict(group_id=group.id,
                            name=group.name,
                            user_group_id=admin_group.user_group_id,
                            permissions=[p.id for p in group.permissions.all()]))


    class BaseAdminGroupFormSet(forms.formsets.BaseFormSet):
        def clean(self):
            if any(self.errors):
                return
            names = []
            for x in range(0, self.total_form_count()):
                form = self.forms[x]
                name = form.cleaned_data['name']
                if name in names:
                    form._errors['name'] = form.error_class([
                        'There is already a group with this name'])
                names.append(name)


    new_admin_group = AdminGroupForm()
    AdminGroupFormSet = formset_factory(AdminGroupForm,
                                        extra=0,
                                        formset=BaseAdminGroupFormSet,
                                        can_delete=True)
    admin_groups = AdminGroupFormSet(initial=initial, prefix='admin_groups')

    if request.method == 'POST' and request.user.has_perm('blue_mgnt.can_manage_settings'):
        if request.POST.get('form', '') == 'new_admin_group':
            new_admin_group = AdminGroupForm(request.POST)
            if new_admin_group.is_valid():
                group = Group.objects.create(name=new_admin_group.cleaned_data['name'])
                for permission_id in new_admin_group.cleaned_data['permissions']:
                    group.permissions.add(Permission.objects.get(pk=permission_id))
                group.save()
                admin_group = models.AdminGroup.objects.create( 
                    group_id=group.id, 
                    user_group_id=new_admin_group.cleaned_data['user_group_id'])
                args = (new_admin_group.cleaned_data['name'], 
                        new_admin_group.cleaned_data['user_group_id'],
                       )
                msg = 'Created admin group: %s %s' % args
                log_admin_action(request, msg)
                return redirect(reverse('blue_mgnt:admin_groups_saved'))
        else:
            admin_groups = AdminGroupFormSet(request.POST, prefix='admin_groups')
            if admin_groups.is_valid():
                for admin_group_form in admin_groups.forms:
                    admin_group = models.AdminGroup.objects.get(
                        pk=admin_group_form.cleaned_data['group_id'])
                    admin_group.user_group_id=admin_group_form.cleaned_data['user_group_id']
                    admin_group.save()
                    group = Group.objects.get(
                        pk=admin_group_form.cleaned_data['group_id'])
                    group.name = admin_group_form.cleaned_data['name']
                    group.permissions.clear()
                    for permission_id in admin_group_form.cleaned_data['permissions']:
                        group.permissions.add(Permission.objects.get(pk=permission_id))
                    group.save()
                    args = (admin_group_form.cleaned_data['name'], 
                            admin_group_form.cleaned_data['user_group_id'],
                        )
                    msg = 'Modified admin group: %s %s' % args
                    log_admin_action(request, msg)
                for admin_group_form in admin_groups.deleted_forms:
                    admin_group = models.AdminGroup.objects.get(
                        pk=admin_group_form.cleaned_data['group_id'])
                    group = Group.objects.get(
                        pk=admin_group_form.cleaned_data['group_id'])
                    admin_group.delete()
                    group.delete()
                    args = (group.name, 
                            admin_group.user_group_id,
                        )
                    msg = 'Deleted admin group: %s %s' % args
                    log_admin_action(request, msg)

                return redirect(reverse('blue_mgnt:admin_groups_saved'))

    return render_to_response('admin_groups.html', dict(
        account_info=account_info,
        user=request.user,
        username=username,
        admin_groups=admin_groups,
        new_admin_group=new_admin_group,
        features=features,
        saved=saved,
        permissions=request.user.user_permissions.all(),
        permissions_count=request.user.user_permissions.count(),
    ),
    RequestContext(request))
