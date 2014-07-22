import json

from django import forms
from django.http import HttpResponse
from django.shortcuts import redirect, render_to_response
from django.template import RequestContext
from django.conf import settings as django_settings
from django.core.cache import cache
from django.views.decorators.csrf import csrf_exempt
from django.core.exceptions import PermissionDenied

from views import enterprise_required, log_admin_action
from netkes.common import read_config_file
from netkes.account_mgr.billing_api import BillingApi

def json_response(request, data):
    return HttpResponse(json.dumps(data), content_type='application/json')

def get_billing_api(config):
    billing_api = BillingApi.create(
        django_settings.BILLING_API_URL,
        config['api_user'],
        config['api_password'],
    )
    return billing_api


class CouponCheckForm(forms.Form):
    coupon_code = forms.CharField()


class CreateSubscriptionForm(forms.Form):
    coupon = forms.CharField(required=False)
    quantity = forms.IntegerField()
    frequency = forms.CharField()
    stripe_memo = forms.CharField(required=False)
    stripe_token= forms.CharField()


@enterprise_required
def billing(request, api, account_info, config, username, saved=False):
    config = read_config_file()
    billing_api = get_billing_api(config)
    stripe_public_key = cache.get('stripe_public_key')
    if not stripe_public_key:
        stripe_public_key = billing_api.stripe_public_key().get('stripe_public_key')
        cache.set('stripe_public_key', stripe_public_key, 60 * 15)

    return render_to_response('billing.html', dict(
        user=request.user,
        username=username,
        account_info=account_info,
        stripe_public_key=stripe_public_key,
    ),
    RequestContext(request))


@csrf_exempt
def check_coupon(request):
    if request.session.get('username') and request.method == 'POST':
        check_form = CouponCheckForm(request.POST)
        if check_form.is_valid():
            coupon_code = check_form.cleaned_data['coupon_code']
            config = read_config_file()
            billing_api = get_billing_api(config)
            return json_response(request, billing_api.fetch_coupon(coupon_code))
    raise PermissionDenied


@csrf_exempt
def create_subscription(request):
    if request.session.get('username') and request.method == 'POST':
        check_form = CreateSubscriptionForm(request.POST)
        if check_form.is_valid():
            config = read_config_file()
            billing_api = get_billing_api(config)
            success = billing_api.create_subscription(
                check_form.cleaned_data['coupon'],
                check_form.cleaned_data['quantity'],
                check_form.cleaned_data['frequency'],
                check_form.cleaned_data['stripe_memo'],
                check_form.cleaned_data['stripe_token'],
            )
            return json_response(request, {
                'success': success,
            })
        return json_response(request, {
            'success': False,
            'msg': check_form.errors,
        })
    raise PermissionDenied
