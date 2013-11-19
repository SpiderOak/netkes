from django.conf.urls import *

from django.contrib import admin
admin.autodiscover()


urlpatterns = patterns('',
    (r'', include('blue_mgnt.urls', namespace='blue_mgnt')),
)
