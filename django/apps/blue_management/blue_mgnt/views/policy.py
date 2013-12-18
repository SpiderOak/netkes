import datetime
from base64 import b32encode

from views import enterprise_required, render_to_response, log_admin_action
from views import ReadOnlyWidget, get_base_url

from django import forms
from django.core.urlresolvers import reverse
from django.forms.formsets import formset_factory
from django.template import RequestContext
from django.shortcuts import redirect

from netkes.account_mgr.user_source import local_source


class PolicyNameForm(forms.Form):
    orig_name = forms.CharField(widget=forms.HiddenInput)
    name = forms.CharField()


class NewPolicyForm(forms.Form):
    name = forms.CharField(max_length=45)


@enterprise_required
def policy(request, api, account_info, config, username, saved=False):
    PolicyFormSet = formset_factory(PolicyNameForm, extra=0, can_delete=True)

    initial = [dict(name='test 1'), dict(name='test 2')]
    policy_formset = PolicyFormSet(initial=initial)
    new_policy = NewPolicyForm()

    if request.method == 'POST':
        if request.POST.get('form', '') == 'new_policy':
            new_user = NewUserForm(request.POST)
            if new_policy.is_valid():
                return redirect('blue_mgnt:policy_saved')
        else:
            policy_formset = PolicyFormSet(request.POST)
            if (request.user.has_perm('blue_mgnt.can_manage_policy') 
                and policy_formset.is_valid()):
                for form in delete_policy_formset.deleted_forms:
                    name = form.cleaned_data['name']
                    #api.delete_user(orig_email)
                    log_admin_action(request, 'delete policy "%s"' % name)
                return redirect(reverse('blue_mgnt:policy_saved'))

    return render_to_response('policy.html', dict(
        user=request.user,
        config=config,
        policies=initial,
        new_policy=new_policy,
        username=username,
        policy_formset=policy_formset,
        features=api.enterprise_features(),
        saved=saved,
        account_info=account_info,
    ),
    RequestContext(request))

HOTKEY_SYMBOL_CHOICES = [
    (y, y) for y in [x for x in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'] \
    + ['SPACE'] + [x for x in '0123456789']
]

SCAN_INTERVAL_CHOICES = [
    (y, y) for y in [
        'Automatic',
        '5 Minutes',
        '15 Minutes',
        '30 Minutes',
        '1 Hour',
        '2 Hours',
        '4 Hours',
        '8 Hours',
        '12 Hours',
        '24 Hours',
        '48 Hours',
    ]
]

SCHEDULE_DAY_CHOICES = [
    (y, y) for y in [
        'Everyday',
        'Monday',
        'Tuesday',
        'Wednesday',
        'Thursday',
        'Friday',
        'Saturday',
        'Sunday',
        'Weekdays',
        'Weekends',
    ]
]

BACKUP_TYPE_CHOICES = [
    (y, y) for y in [
        'Frequency',
        'Time of Day',
    ]
]

class PolicyForm(forms.Form):
    orig_name = forms.CharField(widget=forms.HiddenInput)
    name = forms.CharField(max_length=45)

    #Interface
    autorun = forms.BooleanField(
        required=False,
        label='Launch SpiderOak at OS startup'
    )
    show_close_or_minimize_dialog_on_close = forms.BooleanField(required=False,)
    minimize_to_try_on_close = forms.BooleanField(required=False,)
    launch_minimized_at_startup = forms.BooleanField(
        required=False,
        label='Launch SpiderOak minimized'
    )
    show_splash = forms.BooleanField(
        required=False,
        label="Show the 'Splash' screen at startup"
    )
    use_alternate_tray_icon_style = forms.BooleanField(
        required=False,
        label='Use alternative tray animation style (black)'
    )
    disable_disk_calculations = forms.BooleanField(
        required=False,
        label='Disable disk space calculations during backup selection'
    )
    disable_disk_calculations = forms.BooleanField(
        required=False,
        label='Disable disk space calculations during backup selection'
    )
    show_hotkey_enabled = forms.BooleanField(required=False,)
    show_hotkey_modifier = forms.ChoiceField(
        required=False,
        choices=[
            ('Alt', 'Alt'),
            ('Ctrl', 'Ctrl'),
            ('Alt + Ctrl', 'Alt + Ctrl'),
            ('Alt + Shift', 'Alt + Shift'),
            ('Ctrl + Shift', 'Ctrl + Shift'),
        ]
    )
    show_hotkey_symbol = forms.ChoiceField(
        required=False,
        choices=HOTKEY_SYMBOL_CHOICES 
    )

    #Backup
    dont_archive_files_larger_than_enabled = forms.BooleanField(
        required=False,
        label="Don't backup files larger than"
    )
    dont_archive_files_larger_than_size = forms.IntegerField(
        required=False,
        label='MB'
    )
    dont_archive_files_older_than_enabled = forms.BooleanField(
        required=False,
        label="Don't backup files larger than"
    )
    dont_archive_files_older_than = forms.IntegerField(required=False,)
    dont_archive_files_older_than_period = forms.ChoiceField(
        required=False,
        choices=[
            ('hours', 'hours'),
            ('days', 'days'),
            ('months', 'months'),
            ('years', 'years'),
        ]
    )
    exclude_wildcards = forms.CharField(
        required=False,
        widget=forms.Textarea,
        label="Exclude files matching wildcard"
    )
    exclude_folder_wildcards = forms.CharField(
        required=False,
        widget=forms.Textarea,
        label="Exclude folders matching wildcard"
    )
    enable_previews = forms.BooleanField(
        required=False,
        label="Enable preview generation"
    )

    #Schedule
    full_schedule_backup_type = forms.ChoiceField(
        required=False,
        choices=BACKUP_TYPE_CHOICES
    )
    full_scan_interval = forms.ChoiceField(
        required=False,
        choices=SCAN_INTERVAL_CHOICES
    )
    full_schedule_day = forms.ChoiceField(
        required=False,
        choices=SCHEDULE_DAY_CHOICES
    )
    full_schedule_time = forms.TimeField(
        required=False,
    )

    sync_schedule_backup_type = forms.ChoiceField(
        required=False,
        choices=BACKUP_TYPE_CHOICES
    )
    sync_scan_interval = forms.ChoiceField(
        required=False,
        choices=SCAN_INTERVAL_CHOICES
    )
    sync_schedule_day = forms.ChoiceField(
        required=False,
        choices=SCHEDULE_DAY_CHOICES
    )
    sync_schedule_time = forms.TimeField(
        required=False,
    )

    share_schedule_backup_type = forms.ChoiceField(
        required=False,
        choices=BACKUP_TYPE_CHOICES
    )
    share_scan_interval = forms.ChoiceField(
        required=False,
        choices=SCAN_INTERVAL_CHOICES
    )
    share_schedule_day = forms.ChoiceField(
        required=False,
        choices=SCHEDULE_DAY_CHOICES
    )
    share_schedule_time = forms.TimeField(
        required=False,
    )

    #Local Copy
    secondary_copy_enabled = forms.BooleanField(
        required=False,
        label="Keep my own copy of all archived data blocks"
    )
    secondary_copy_location = forms.CharField(
        required=False,
        label="Location"
    )
    secondary_copy_hostname = forms.CharField(
        required=False,
        label="Hostname"
    )
    secondary_copy_port = forms.CharField(
        required=False,
        label="Hostname"
    )
    secondary_copy_username = forms.CharField(
        required=False,
        label="Username"
    )
    secondary_copy_password = forms.CharField(
        required=False,
        label="Password"
    )
    
    #Proxy
    http_proxy_enabled = forms.BooleanField(
        required=False,
        label="Connect using a HTTP Proxy Server"
    )
    http_proxy_host = forms.CharField(
        required=False,
        label="HTTP Proxy Server Hostname"
    )
    http_proxy_port = forms.CharField(
        required=False,
        label="HTTP Proxy Username"
    )
    http_proxy_username = forms.CharField(
        required=False,
        label="HTTP Proxy Password"
    )
    limit_bandwidth_enabled = forms.BooleanField(
        required=False,
        label="Limit Bandwidth"
    )
    limit_upload_bucket = forms.IntegerField(
        required=False,
        label="Max Upload KB/s"
    )

    #General
    downloads_locations = forms.CharField(
        required=False,
    )

    def clean(self):
        cleaned_data = super(PolicyForm, self).clean()
        required_together = (
            ('show_hotkey_enabled', 'show_hotkey_modifier'),
            ('show_hotkey_enabled', 'show_hotkey_symbol'),
            ('dont_archive_files_larger_than_enabled', 
             'dont_archive_files_larger_than_size'),
            ('dont_archive_files_older_than', 
             'dont_archive_files_older_than_period'),
        )

        msg = "This Field is required"
        for field1, field2 in required_together:
            if cleaned_data.get(field1) and not cleaned_data.get(field2):
                self._errors[field2] = self.error_class([msg])

                del cleaned_data[field2]

        return cleaned_data
        



@enterprise_required
def policy_detail(request, api, account_info, config, username, name, saved=False):
    initial = {
        'orig_name': name,
        'name': name,
    }

    policy = PolicyForm(initial=initial)

    if request.method == 'POST':
        policy = PolicyForm(request.POST)
        if policy.is_valid():
            name = policy.cleaned_data['name']
            log_admin_action(request, 'update policy "%s"' % name)
            return redirect(reverse('blue_mgnt:policy_detail_saved', args=(name, )))

    return render_to_response('policy_detail.html', dict(
        user=request.user,
        config=config,
        policy=policy,
        name=name,
        username=username,
        features=api.enterprise_features(),
        saved=saved,
        account_info=account_info,
    ),
    RequestContext(request))















