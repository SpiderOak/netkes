from django.conf.urls import include, url

from django.contrib import admin
admin.autodiscover()


urlpatterns = [
    url(r'', include('blue_mgnt.urls', namespace='blue_mgnt')),
]
