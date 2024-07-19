# eventsphere/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('signup/', views.SignUp.as_view(), name='signup'),
    path('verify/', views.Verify.as_view(), name='verify_signup'),
    path('signin/', views.SignIn.as_view(), name='signin'),
    path('signout/', views.SignOut.as_view(), name='signout'),
    path('retrieve-data/', views.RetrieveUserData.as_view(), name='retrieve_data'),
    path('edit-user/', views.EditUser.as_view(), name='edit_user'),
    path('create-event/', views.CreateEvent.as_view(), name='create_event'),
    path('delete-event/', views.DeleteEvent.as_view(), name='retrieve_events'),
    path('search/', views.SearchPublicTable.as_view(), name='search'),
    path('send-friend-request/', views.SendFriendRequest.as_view(), name='retrieve_events'),
    path('decide-friend-request/', views.DecideFriendRequest.as_view(), name='retrieve_events'),
]
