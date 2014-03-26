from django.conf.urls import *

urlpatterns = patterns('',
    (r'^', include('omva.enterprise.urls')),
)
