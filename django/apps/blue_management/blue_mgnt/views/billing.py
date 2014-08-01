import json

from django import forms
from django.http import HttpResponse
from django.shortcuts import redirect, render_to_response
from django.template import RequestContext
from django.conf import settings as django_settings
from django.core.cache import cache
from django.views.decorators.csrf import csrf_exempt
from django.core.exceptions import PermissionDenied

from views import enterprise_required, log_admin_action, get_billing_api

def json_response(request, data):
    return HttpResponse(json.dumps(data), content_type='application/json')


class CouponCheckForm(forms.Form):
    coupon_code = forms.CharField()


class CreateSubscriptionForm(forms.Form):
    coupon = forms.CharField(required=False)
    quantity = forms.IntegerField()
    frequency = forms.CharField()
    stripe_memo = forms.CharField(required=False)
    stripe_token = forms.CharField(required=False)


@enterprise_required
def billing(request, api, account_info, config, username, saved=False):
    billing_api = get_billing_api(config)
    billing_info = cache.get('billing_info')
    if not billing_info:
        billing_info = billing_api.billing_info()
        cache.set('billing_info', billing_info, 60 * 15)
    current_plan = billing_info.get('current_plan')

    ctx = dict(
        user=request.user,
        username=username,
        account_info=account_info,
        billing_info=billing_info,
    )
    tmpl = 'billing.html'
    if current_plan and current_plan['status'] == 'pending':
        tmpl = 'billing_pending.html'
        cache.delete('billing_info')
       
    return render_to_response(tmpl, ctx, RequestContext(request))


@csrf_exempt
@enterprise_required
def check_coupon(request, api, account_info, config, username):
    if request.session.get('username') and request.method == 'POST':
        check_form = CouponCheckForm(request.POST)
        if check_form.is_valid():
            coupon_code = check_form.cleaned_data['coupon_code']
            billing_api = get_billing_api(config)
            return json_response(request, billing_api.fetch_coupon(coupon_code))
    raise PermissionDenied


@csrf_exempt
@enterprise_required
def create_subscription(request, api, account_info, config, username):
    if request.session.get('username') and request.method == 'POST':
        check_form = CreateSubscriptionForm(request.POST)
        if check_form.is_valid():
            quantity = check_form.cleaned_data['quantity']
            if account_info['total_users'] > quantity:
                return json_response(request, {
                    'success': False,
                    'msg': 'Quantity lower than current users',
                })
            billing_api = get_billing_api(config)
            success = billing_api.create_subscription(
                check_form.cleaned_data['coupon'],
                check_form.cleaned_data['quantity'],
                check_form.cleaned_data['frequency'],
                check_form.cleaned_data['stripe_memo'],
                check_form.cleaned_data['stripe_token'],
            )
            if success: 
                cache.delete('billing_info')
            return json_response(request, {
                'success': success,
            })
        return json_response(request, {
            'success': False,
            'msg': check_form.errors,
        })
    raise PermissionDenied
