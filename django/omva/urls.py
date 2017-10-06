from django.conf.urls import include, url

urlpatterns = [
    url(r'^openmanage/', include('openmanage.urls')),
    url(r'^', include('omva.enterprise.urls')),
]
