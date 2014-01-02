from django.conf import settings

def blue_common(request):
    return dict(
        management_vm=getattr(settings, 'MANAGEMENT_VM', False),
        private_cloud=getattr(settings, 'PRIVATE_CLOUD', False),
    )
