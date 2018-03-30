import re
import logging
from collections import namedtuple, OrderedDict
import inflection

from django import forms
from django.http import Http404
from django.core.cache import cache
from django.core import validators
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt

from views import enterprise_required


LOG = logging.getLogger(__file__)

# Store Preference data as a namedtuple
Preference = namedtuple('Preference', [
    'name',
    'description',
    'field_type',
    'choices',
    'parent',
    'conditional_parent_value']
)

ROOT_INHERIT_CHOICES = (
    ('--set--', 'Managed'),
    ('--unset--', "User controlled")
)

INHERIT_CHOICES = (('--inherit--', 'Inherit'), ) + ROOT_INHERIT_CHOICES

DEFAULTS = {
    "Autorun": True,
    "EnableAutomaticScan": True,
    "EnablePreviews": True,
    "FullScheduleEnable": False,
    "HttpProxyEnabled": False,
    "windowsnewerthanxpBackupSelectionEnabled": True,
    "windowsnewerthanxpBackupSelectionScope": "atleast",
    "windowsnewerthanxpBackupSelectionType": "basic",
    "windowsnewerthanxpBasicBackupSelectionDesktop": True,
    "windowsnewerthanxpBasicBackupSelectionDocuments": True,
}


class ListField(forms.Field):
    """ Accepts comma separated strings and returns them as a list """

    def __init__(self, *args, **kwargs):
        super(ListField, self).__init__(*args, **kwargs)

        if not hasattr(self, 'empty_values'):
            # Set empty_values if it doesn't exist. This attribute was added
            # to fields after the current version in use (1.5.10)
            self.empty_values = validators.EMPTY_VALUES

    def prepare_value(self, value):
        """ Convert the list to a comma separate string for use in the form """
        if value in self.empty_values:
            return ''
        if isinstance(value, list):
            return "\n".join(value)
        return value.lstrip("[").rstrip("]")

    def to_python(self, value):
        """ Return the value as a list or an empty list """
        if isinstance(value, list):
            return value
        if isinstance(value, (str, unicode)):
            return [i.strip() for i in value.splitlines() if i]
        return []


def _build_preference(pref, parent=None):
    """ Convert dictionary to namedtuple """
    return Preference(
        pref['name'],
        pref['description'],
        pref['type'],
        pref['choices'],
        parent,
        pref['conditional_parent_value'],
    )


def _parse_preferences(preferences, parent=None):
    """ Create a dictionary with the required info from preferences """

    for pref in preferences:
        if pref.get('name'):
            yield _build_preference(pref, parent=parent)

        for f in pref['fields']:
            # Pass the field as a tuple since an iterable is expected
            for i in _parse_preferences((f, ), parent=pref.get('name')):
                yield i


def _get_preferences(api):
    """ Get preferences from cache or set them if they are not there """

    prefs = cache.get('PREFERENCES')
    if not prefs:
        # Convert results to a list so they can be cached
        prefs = list(_parse_preferences(api.get_device_preferences()))
        prefs.sort()
        cache.set('PREFERENCES', prefs, 3600)  # Cache preferences for 1 hour
    return prefs


def _build_choices(choices):
    """ Yield choices in a format that ChoiceField can use """
    for choice in choices:
        yield (choice, choice)


def _field_type(preference, required=True, choices=None):
    """ Get the correct Django forms field based on the provided value """

    platforms = ['mac', 'linux', 'windowsxp', 'windowsnewerthanxp']
    label = preference.description
    if not label or any(preference.name.startswith(platform) for platform in platforms):
        label = inflection.humanize(inflection.underscore(preference.name))

    if 'Windowsxp' in label:
        label = label.replace('Windowsxp', 'Windows XP')
    if 'Windowsnewerthanxp' in label:
        label = label.replace('Windowsnewerthanxp', 'Windows Vista+')

    if preference.field_type == 'string[]':
        widget = forms.Textarea()
        if preference.name in ['macAdvancedBackupSelectionSelected',
                               'macAdvancedBackupSelectionDeselected']:
            widget.attrs['placeholder'] = '$HOME/Pictures\n$HOME/Documents'
        if preference.name in ['linuxAdvancedBackupSelectionSelected',
                               'linuxAdvancedBackupSelectionDeselected']:
            widget.attrs['placeholder'] = '$HOME/pictures\n$HOME/documents'
        if preference.name in ['windowsxpAdvancedBackupSelectionSelected',
                               'windowsxpAdvancedBackupSelectionDeselected']:
            widget.attrs['placeholder'] = '%USERPROFILE%\My Documents\n%USERPROFILE%\My Pictures'
        if preference.name in ['windowsnewerthanxpAdvancedBackupSelectionSelected',
                               'windowsnewerthanxpAdvancedBackupSelectionDeselected']:
            widget.attrs['placeholder'] = '%USERPROFILE%\Documents\n%USERPROFILE%\Pictures'
        return ListField(required=required, label=label, widget=widget)

    if preference.field_type == 'string':
        if choices:
            return forms.ChoiceField(
                choices=_build_choices(choices),
                required=required,
                label=label
            )
        return forms.CharField(required=required, label=label)

    if preference.field_type == 'integer':
        return forms.IntegerField(required=required, label=label, min_value=0)

    if preference.field_type == 'boolean':
        return forms.BooleanField(required=False, label=label)

    LOG.error("Unable to get field type. {} is an invalid option".format(preference.field_type))  # NOQA


def _attrs_from_preference(preference):
    """ Get widget attributes based on the provided preference """

    if preference.parent and preference.conditional_parent_value:
        cpv = preference.conditional_parent_value

        # Change bool to string
        if isinstance(cpv, bool):
            if cpv:
                cpv = 'True'
            else:
                cpv = 'False'

        return {'data-parent': preference.parent,
                'data-conditional-parent-value': cpv}
    return {}


class PolicyForm(forms.Form):
    id = forms.IntegerField(required=False, widget=forms.HiddenInput)
    name = forms.CharField(max_length=50)

    def __init__(self, *args, **kwargs):
        self.api = kwargs.pop('api')
        self._preferences = _get_preferences(self.api)

        self._preferences_dict = {}
        for p in self._preferences:
            self._preferences_dict[p.name] = p

        self._policy = kwargs.pop('policy', None)
        if not self._policy:
            self._policy = {
                'id': None,
                'name': '',
                'inherits_from': None,
                'policy': {},
            }

        self._inherit = kwargs.pop('inherit', None) or self._policy['inherits_from']  # NOQA

        if self._inherit:
            self._parent_policy = _policy_from_id_or_404(self.api, self._inherit)  # NOQA
        else:
            self._parent_policy = None

        if 'initial' not in kwargs:
            kwargs['initial'] = {}

        kwargs['initial'].update(
            {'id': self._policy['id'], 'name': self._policy['name']}
        )

        super(PolicyForm, self).__init__(*args, **kwargs)

        self._add_inherit_from_field()
        self._add_fields_from_preferences()

        # Set all inheritance fields to --unset-- if this is a brand new policy
        if not any([self._policy['id'], self._inherit, self._policy.get('inherits_from')]):  # NOQA
            self._set_all_inheritance_fields(inheritance='--unset--')

        self._set_initial_values_from_policy()

        # Set all inheritance fields to --inherit-- if we are copying a policy
        if self._inherit and not self._policy.get('inherits_from'):
            self._set_all_inheritance_fields()

        self._sort_fields()

    def _parent_choices(self):
        """ Get a list of parent choices used for inheritance """
        policies = self.api.list_policies()
        choices = [('', '----------')]
        choices.extend(
            [(p['id'], p['name']) for p in policies if not p['inherits_from']])
        return choices

    def _add_inherit_from_field(self):
        """ Create a TypedChoiceField that coerces to integer and uses
        api.list_policies to provide inheritance choices """

        self.fields['inherit_from'] = forms.IntegerField(
            required=False, widget=forms.HiddenInput, initial=self._inherit)

    def _add_fields_from_preferences(self):
        """ Add fields of the correct type based on preferences """
        for pref in self._preferences:
            # Currently mark all fields as being unrequired
            new_field = _field_type(
                pref, False, pref.choices)

            # Only add the new field to fields if it exists
            if new_field:
                self.fields[pref.name] = new_field

                # Set inherit choices
                if self._inherit or self.data.get('inherit_from'):
                    inherit_choices = INHERIT_CHOICES
                else:
                    inherit_choices = ROOT_INHERIT_CHOICES

                if pref.name in ['DeletedItemsAutomaticPurge',
                                 'HistoricalVersionAutomaticPurge']:
                    inherit_choices = [x for x in inherit_choices if x[0] != '--unset--']

                inherit_field_name = "_".join([pref.name, 'inheritance'])
                inherit_field = forms.ChoiceField(choices=inherit_choices)
                inherit_field.widget.attrs['class'] = 'policy-inherit-select'
                self.fields[inherit_field_name] = inherit_field

                # Add attrs to the field (e.g data-parent)
                self.fields[pref.name].widget.attrs.update(
                    _attrs_from_preference(pref)
                )

    def _set_all_inheritance_fields(self, inheritance='--inherit--'):
        """ A method for quickly setting all inheritance fields """
        for key in self.fields.iterkeys():
            if key.endswith("_inheritance"):
                self.fields[key].initial = inheritance

    def _set_initial_values_from_policy(self):
        """ Set the initial value for the current form fields based on the
        provided policy and inheritance setting.
        """

        exclude = ['name', 'id', 'inherit_from']

        for field in self.fields:

            # The fields in exclude won't have inheritance fields
            if field in exclude or field.endswith('inheritance'):
                continue

            inheritance_field = '{}_inheritance'.format(field)
            value = self._policy['policy'].get(field)

            if self._parent_policy:
                parent_value = self._parent_policy['policy'].get(field)
                if parent_value == '--unset--':
                    parent_value = None
            else:
                parent_value = None

            # If there is a value, but it's not in the inheritance fields,
            # set the value and set inheritance to --set--
            if value is not None and value not in ('--inherit--', '--unset--'):
                self.fields[field].initial = value
                self.fields[inheritance_field].initial = '--set--'

            # If the value isunset, clear the field value and set the
            # inheritance field value
            elif value == '--unset--':
                self.fields[field].initial = None
                self.fields[inheritance_field].initial = value

            elif self._inherit and parent_value is not None:
                self.fields[field].initial = parent_value
                self.fields[inheritance_field].initial = '--inherit--'

            # Otherwise, if there is no value, set this to unset
            else:
                # Set default value
                if not self._inherit and field in DEFAULTS:
                    self.fields[field].initial = DEFAULTS[field]
                    self.fields[inheritance_field].initial = '--set--'
                else:
                    self.fields[field].initial = None
                    self.fields[inheritance_field].initial = '--unset--'

    def _create_ordered_fields(self):
        # Store the fields as parent: [child, child, child]
        ordered_fields = OrderedDict(
            {'id': [], 'name': [], 'inherit_from': []}
        )

        for key in self.fields:
            # Add the _inheritance field order later. Skip them for now
            if key.endswith('_inheritance'):
                continue

            # Get the actual field object instead of just using the field name
            field = self.fields.get(key)
            if 'data-parent' in field.widget.attrs:
                parent_key = field.widget.attrs['data-parent']
                if parent_key not in ordered_fields:
                    ordered_fields[parent_key] = []
                if key not in ordered_fields[parent_key]:
                    ordered_fields[parent_key].append(key)
            elif key not in ordered_fields:
                ordered_fields[key] = []
        return ordered_fields

    def _sort_fields(self):
        """ Make sure fields are in their expected order
        Current order should be:
        - id
        - name
        - inherit_from

        Followed by the generated fields, in alphabetical order. They should
        look as follows:

        - parent
        - parent_inheritance
        - child
        - child_inheritance

        NOTE: It is easier to render it with the inheritance field after
        the value field than to render it before the value field so that we
        can ensure the field label comes first.

        Children should be after their parents, regardless of alphabetical
        order.

        """
        ordered_fields = self._create_ordered_fields()

        fields = ['id', 'name', 'inherit_from']
        for key, children in ordered_fields.iteritems():

            if key in ('id', 'name', 'inherit_from'):
                continue

            # Add the key back in, then the inheritance key
            if key not in fields:
                fields.append(key)

            # Add the inheritance fields back in. Do this before appending the
            # previous key to have inheritance fields show before the field
            # being referenced
            inherit_field = "_".join([key, 'inheritance'])
            if inherit_field not in fields:
                fields.append(inherit_field)

            # Add the child fields after the parents to guarantee they are in
            # the correct order, instead of hoping children will always come
            # after their parent alphabetically
            for child in children:
                inherit_child = "_".join([child, 'inheritance'])

                try:
                    parent_index = fields.index(inherit_field)
                except ValueError:
                    parent_index = -1

                if child not in fields:
                    if parent_index >= 0:
                        fields.insert(parent_index + 1, child)
                    else:
                        fields.append(child)

                if inherit_child not in fields:
                    fields.insert(fields.index(child) + 1, inherit_child)

        # Set the keyOrder based on the list of ordered keys
        self.fields.keyOrder = fields

    def _validate_child(self, preference):
        """ Make sure the parent value allows the child field to be set """

        parent_value = self.cleaned_data.get(preference.parent)

        # If the parent value is in INHERIT_CHOICES, the child value should be
        # removed
        if parent_value in INHERIT_CHOICES:
            return False

        if isinstance(preference.conditional_parent_value, list):
            valid = parent_value in preference.conditional_parent_value
        else:
            valid = parent_value == preference.conditional_parent_value

        if not valid:
            return False

        # If this has a parent, make sure the parent is also valid
        if valid and self._preferences_dict[preference.parent].parent is not None:  # NOQA
            return self._validate_child(self._preferences_dict[preference.parent])  # NOQA

        return True

    def _validate_preference(self, preference):
        """ Run additional validation on each preference if needed """

        if preference.field_type == "integer" and \
           preference.name in self.cleaned_data and \
           self.cleaned_data[preference.name] is None:
            return False

        if preference.conditional_parent_value is None:
            return True

        return self._validate_child(preference)

    def clean_name(self):
        name = self.cleaned_data.get("name", '').strip()
        if not name:
            raise forms.ValidationError("Name must not be empty")
        return name

    def clean(self):
        """ Clean the data based on preference requirements """

        # Remove INHERIT_CHOICE values during clean so validation works
        for k, v in self.data.iteritems():
            if not k.endswith('_inheritance') and v in INHERIT_CHOICES:
                self.data[k] = None

        super(PolicyForm, self).clean()

        # Remove inheritance fields and apply their values where needed
        self._sanitize_inheritance()

        for preference in self._preferences:
            if not self._validate_preference(preference):
                try:
                    del self.cleaned_data[preference.name]
                except KeyError:
                    pass

        return self.cleaned_data

    def _sanitize_inheritance(self):
        """ Change the values of fields when inheritance is set to --unset--
        or --inherit-- and remove all fields from cleaned_data that end in
        _inheritance """

        suffix = '_inheritance'
        remove_patt = re.compile(suffix + '$')
        inheritance_values = ('--inherit--', '--unset--')

        # Set inheritance values (Note: Can't use iterkeys because we are
        # modifying the dictionary)
        for k in self.cleaned_data.keys():
            if k.endswith(suffix):
                val = self.cleaned_data.pop(k)
                if val in inheritance_values:
                    # Set the value to --inherit-- or --unset--
                    self.cleaned_data[remove_patt.sub('', k)] = val

    def save(self, create=False):
        """ Save the existing policy or create a new policy if create is True
        """

        policy_id = self.cleaned_data.pop('id')

        policy_info = {
            'name': self.cleaned_data.pop('name'),
            'inherits_from': self.cleaned_data.pop('inherit_from', None),
            'policy': self.cleaned_data,
        }

        if create:
            self.api.create_policy(policy_info)

        elif policy_id:
            self.api.edit_policy(policy_id, policy_info)


def _build_parent_dict(policies):
    """ Return a dictionary full of policies names mapped to IDs,
    e.g. {1: 'My policy', 2: 'My other policy'}
    """
    parent_dict = {}
    for p in policies:
        parent_dict[p['id']] = p['name']
    return parent_dict


def _assign_parents(policies):
    """ Set the parent name for each policy """
    parents = _build_parent_dict(policies)

    for policy in policies:
        if policy['inherits_from']:
            policy['parent'] = parents[policy['inherits_from']]
    return policies


def _policy_from_id_or_404(api, policy_id):
    """ Get the policy or raise a 404 """
    try:
        return api.get_policy(int(policy_id))
    except api.NotFound:
        raise Http404


@enterprise_required
def policy_list(request, api, account_info, config, username):
    """ Get the list of policies and assign their parent names to each policy
    """
    policies = _assign_parents(api.list_policies())
    return render(request, 'policy_list.html', {'policies': policies})


@csrf_exempt
@enterprise_required
def policy_create(request, api, account_info, config, username):  # NOQA
    """ Get a policy from the provided policy ID """

    inherit = request.GET.get('inherit')

    if inherit:
        policy = _policy_from_id_or_404(api, inherit)
    else:
        policy = None

    if request.method == 'POST':
        form = PolicyForm(
            request.POST,
            api=api,
            policy=policy,
            inherit=inherit,
        )
        if form.is_valid():
            form.save(create=True)
            return redirect('blue_mgnt:policy_list')
    else:
        form = PolicyForm(
            api=api,
            policy=policy,
            inherit=inherit,
        )

    return render(
        request,
        'policy_detail.html', {
            'form': form,
            'device_preferences': api.get_device_preferences(),
        })


@csrf_exempt
@enterprise_required
def policy_detail(request, api, account_info, config, username, policy_id):  # NOQA
    """ Get a policy from the provided policy ID """

    # Get the policy or raise a 404
    policy = _policy_from_id_or_404(api, policy_id)

    if request.method == 'POST':
        form = PolicyForm(
            request.POST,
            api=api,
            policy=policy,
        )
        if form.is_valid():
            form.save()
            return redirect('blue_mgnt:policy_list')
    else:
        form = PolicyForm(
            api=api,
            policy=policy,
        )

    return render(
        request,
        'policy_detail.html', {
            'form': form,
            'policy': policy,
            'device_preferences': api.get_device_preferences(),
        })


@csrf_exempt
@enterprise_required
def policy_delete(request, api, account_info, config, username, policy_id, delete=False):  # NOQA
    """ Return a delete confirmation page or delete the policy based on the
    delete keyword argument """

    policy_id = int(policy_id)
    # Get the policy or raise a 404
    try:
        policy = api.get_policy(policy_id)
    except api.NotFound:
        raise Http404

    delete_success = False
    in_use = False

    # If the delete keyword argument is True, confirmation has been provided
    if request.method == 'POST' and delete:
        delete_button_val = request.POST['delete-button']

        if delete_button_val == 'cancel':
            return redirect('blue_mgnt:policy_list')
        elif delete_button_val == 'delete':
            try:
                api.delete_policy(policy_id)
                delete_success = True
                return redirect('blue_mgnt:policy_list')
            except api.PolicyInUse:
                in_use = True

    return render(
        request,
        'policy_delete.html',
        {'policy': policy, 'in_use': in_use, 'deleted': delete_success}
    )
