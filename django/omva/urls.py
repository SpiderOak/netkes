from django.conf.urls import *

urlpatterns = patterns('',
    (r'^openmanage/', include('openmanage.urls')),
    (r'^', include('omva.enterprise.urls')),
)
