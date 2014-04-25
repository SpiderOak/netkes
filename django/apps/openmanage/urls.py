from django.conf.urls import *
from views import *

urlpatterns = patterns('',
    (r'^authsession/$', start_auth_session, {}, 'auth_session'),
    (r'^auth/$', authenticate_user, {}, 'auth'),
    (r'^data/$', read_data, {}, 'read_data'),
    (r'^password/$', password, {}, 'password'),
)
