from django.conf.urls import url
import views

urlpatterns = [
    url(r'^authsession/$', views.start_auth_session, {}, 'auth_session'),
    url(r'^auth/$', views.authenticate_user, {}, 'auth'),
    url(r'^data/$', views.read_data, {}, 'read_data'),
    url(r'^password/$', views.password, {}, 'password'),
]
