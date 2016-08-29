from django.shortcuts import render_to_response

from views import enterprise_required


@enterprise_required
def policy_list(request, api, account_info, config, username):
    return render_to_response(
        "policy_list.html", {'policies': api.list_policies()})


@enterprise_required
def policy_detail(request, api, account_info, config, username, policy_id):
    return render_to_response(
        "policy_detail.html", {'policy': api.get_policy(int(policy_id))})
