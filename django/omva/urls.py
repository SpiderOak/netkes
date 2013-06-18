from django.conf.urls.defaults import *

urlpatterns = patterns('',
    (r'^', include('omva.enterprise.urls')),
)
