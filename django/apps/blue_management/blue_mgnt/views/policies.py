import re
import logging
from collections import namedtuple

from django import forms
from django.http import Http404
from django.core.cache import cache
from django.core import validators
from django.shortcuts import render_to_response, redirect
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
    ('--set--', 'Set'),
    ('--unset--', "Don't Set")
)

INHERIT_CHOICES = (('--inherit--', 'Inherit'), ) + ROOT_INHERIT_CHOICES



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
            return ", ".join(value)
        return value.lstrip("[").rstrip("]")

    def to_python(self, value):
        """ Return the value as a list or an empty list """
        if isinstance(value, list):
            return value
        if isinstance(value, (str, unicode)):
            return [i.strip() for i in value.split(",") if i]
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

    cache.delete('PREFERENCES')
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


def _field_type(field_type, required=True, choices=None):
    """ Get the correct Django forms field based on the provided value """

    if field_type == 'string[]':
        return ListField(required=required)

    if field_type == 'string':
        if choices:
            return forms.ChoiceField(
                choices=_build_choices(choices), required=required)
        return forms.CharField(required=required)

    if field_type == 'integer':
        return forms.IntegerField(required=required)

    if field_type == 'boolean':
        return forms.BooleanField(required=False)

    LOG.error("Unable to get field type. {} is an invalid option".format(field_type))  # NOQA


def _attrs_from_preference(preference):
    """ Get widget attributes based on the provided preference """
    if preference.parent and preference.conditional_parent_value:
        return {'data-parent': preference.parent,
                'data-conditional-parent-value': preference.conditional_parent_value}  # NOQA
    return {}


class PolicyForm(forms.Form):
    id = forms.IntegerField(required=False, widget=forms.HiddenInput)
    name = forms.CharField()

    def __init__(self, *args, **kwargs):
        self.api = kwargs.pop('api')
        self._preferences = _get_preferences(self.api)

        self._preferences_dict = {}
        for p in self._preferences:
            self._preferences_dict[p.name] = p

        self._policy = kwargs.pop('policy')

        if 'initial' not in kwargs:
            kwargs['initial'] = {}

        kwargs['initial'].update(
            {'id': self._policy['id'], 'name': self._policy['name']}
        )

        super(PolicyForm, self).__init__(*args, **kwargs)

        for pref in self._preferences:
            # Currently mark all fields as being unrequired
            new_field = _field_type(
                pref.field_type, False, pref.choices)

            # Only add the new field to fields if it exists
            if new_field:
                self.fields[pref.name] = new_field
                inherit_choices = INHERIT_CHOICES if self._policy['inherits_from'] else ROOT_INHERIT_CHOICES

                if not pref.parent:
                    self.fields["_".join([pref.name, 'inheritance'])] = forms.ChoiceField(choices=inherit_choices)

                # Add attrs to the field (e.g data-parent)
                self.fields[pref.name].widget.attrs.update(
                    _attrs_from_preference(pref)
                )

        for key, value in self._policy['policy'].iteritems():
            if key in self.fields:
                if value in ('--inherit--', '--unset--'):
                    self.fields["_".join([key, 'inheritance'])].initial = value
                else:
                    self.fields[key].initial = value
            else:
                LOG.error('Unable to set value for {}'.format(key))

    def _validate_child(self, preference):
        """ Make sure the parent value allows the child field to be set """

        parent_value = self.cleaned_data.get(preference.parent)

        # If the parent value is in INHERIT_CHOICES, the child value should be
        # removed
        if parent_value in INHERIT_CHOICES:
            return False

        if isinstance(preference, list):
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

        if not preference.conditional_parent_value:
            return True

        return self._validate_child(preference)

    def clean(self):
        """ Clean the data based on preference requirements """

        # Remove INHERIT_CHOICE values during clean so validation works
        for k, v in self.data.iteritems():
            if not k.endswith('_inheritance') and v in INHERIT_CHOICES:
                self.data[k] = None

        # Clean and validate the data
        super(PolicyForm, self).clean()

        # Remove inheritance fields and apply their values where needed
        self._sanitize_inheritance()

        for preference in self._preferences:
            if not self._validate_preference(preference):
                del self.cleaned_data[preference.name]

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
                    self.cleaned_data[remove_patt.sub('', k)] = val

    def save(self, create=False):
        """ Save the existing policy or create a new policy if create is True
        """

        policy_id = self.cleaned_data.pop('id')

        policy_info = {
            'name': self.cleaned_data.pop('name'),
            'policy': self.cleaned_data,
        }

        if create:
            if policy_id:
                policy_info['inherits_from'] = policy_id
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


@enterprise_required
def policy_list(request, api, account_info, config, username):
    """ Get the list of policies and assign their parent names to each policy
    """
    policies = _assign_parents(api.list_policies())
    return render_to_response('policy_list.html', {'policies': policies})


@csrf_exempt
@enterprise_required
def policy_detail(request, api, account_info, config, username, policy_id, create=False):  # NOQA
    """ Get a policy from the provided policy ID """

    # Get the policy or raise a 404
    try:
        policy = api.get_policy(int(policy_id))
    except api.NotFound:
        raise Http404

    # Don't allow inherting from a policy that also inherits from a parent
    if create and policy.get('inherits_from'):
        missing_form_error = "Sorry, but you are unable to inherit from this policy"  # NOQA
        return render_to_response(
            'policy_detail.html',
            {'form': None, 'missing_form_error': missing_form_error}
        )

    if request.method == 'POST':
        form = PolicyForm(
            request.POST,
            api=api,
            policy=policy,
        )
        if form.is_valid():
            form.save(create=create)
            return redirect('blue_mgnt:policy_list')
    else:
        form = PolicyForm(
            api=api,
            policy=policy,
        )

    return render_to_response(
        'policy_detail.html', {
            'form': form,
            'policy': policy,
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

    return render_to_response(
        'policy_delete.html',
        {'policy': policy, 'in_use': in_use, 'deleted': delete_success}
    )
