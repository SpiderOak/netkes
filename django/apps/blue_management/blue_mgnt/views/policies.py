import logging
from collections import namedtuple

from django import forms
from django.http import Http404
from django.core.cache import cache
from django.shortcuts import render_to_response
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

    # FIXME: 'string[]' needs a custom comma separated field
    if field_type == 'string' or field_type == 'string[]':
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

                # Add attrs to the field (e.g data-parent)
                self.fields[pref.name].widget.attrs.update(
                    _attrs_from_preference(pref)
                )

        for key, value in self._policy['policy'].iteritems():
            if key in self.fields:
                self.fields[key].initial = value
            else:
                LOG.error('Unable to set value for {}'.format(key))

    def _validate_child(self, preference):
        """ Make sure the parent value allows the child field to be set """

        parent_value = self.cleaned_data.get(preference.parent)

        if isinstance(preference, list):
            valid = parent_value in preference.conditional_parent_value
        else:
            valid = parent_value == preference.conditional_parent_value

        if not valid:
            return False

        # If this has a parent, make sure the parent is also valid
        if valid and self._preferences_dict[preference.parent].parent is not None:
            return self._validate_child(self._preferences_dict[preference.parent])

        return True

    def _validate_preference(self, preference):
        """ Run additional validation on each preference if needed """

        if not preference.conditional_parent_value:
            return True

        return self._validate_child(preference)

    def clean(self):
        """ Clean the data based on preference requirements """
        super(PolicyForm, self).clean()

        for preference in self._preferences:
            if not self._validate_preference(preference):
                del self.cleaned_data[preference.name]

        return self.cleaned_data

    def save(self):
        """ Save the updated policy """

        policy_id = self.cleaned_data.pop('id')

        policy_info = {
            'name': self.cleaned_data.pop('name'),
            'policy': self.cleaned_data,
        }

        if policy_id:
            self.api.edit_policy(policy_id, policy_info)


@enterprise_required
def policy_list(request, api, account_info, config, username):
    return render_to_response(
        'policy_list.html', {'policies': api.list_policies()})


@csrf_exempt
@enterprise_required
def policy_detail(request, api, account_info, config, username, policy_id):
    """ Get a policy from the provided policy ID """

    # Get the policy or raise a 404
    try:
        policy = api.get_policy(int(policy_id))
    except api.NotFound:
        raise Http404

    if request.method == 'POST':

        form = PolicyForm(
            request.POST,
            api=api,
            policy=policy,
        )
        if form.is_valid():
            form.save()
    else:

        form = PolicyForm(
            api=api,
            policy=policy,
        )

    return render_to_response(
        'policy_detail.html', {'form': form})


@enterprise_required
def policy_create(request, api, account_info, config, username):
    return render_to_response(
        'policy_create.html', {'current_policies': api.list_policies()})
