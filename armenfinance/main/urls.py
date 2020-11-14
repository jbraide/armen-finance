from django.urls import path

'''
home, privacy policy, Payment Policy views
'''

from .views import index, logout_view,contact, about, register,terms_and_condition, privacy_policy, login, activation_sent, change_password

# dashboard routes
from .views import dashboard, id_verification, account_upgrade, create_profile,edit_profile, fund_account, trading_history, withdraw_funds, transfer_to_armen, transfer_to_foreign_account

# validation routes
from .views import validate_login, validate_registration, activate, token_auth
from . import views

app_name = 'main'

urlpatterns = [
    # home page
    path('', index, name="index"),
    # about
    path('about/', about, name='about'),
    path('contact/', contact, name='contact'),
    # terms and conditions, Privacy policy
    path('terms-and-conditions/', terms_and_condition, name='terms-and-conditions'),
    path('privacy-policy', privacy_policy, name='privacy-policy'),
    # dashboard routes
    path('dashboard/', dashboard, name="dashboard"),
    path('transfer/armen',transfer_to_armen,name='transfer-to-armen'),
    path('transfer/foreign-account',transfer_to_foreign_account,name='transfer-to-foreign-account'),
    path('fund-account/', fund_account, name='fund_account'), 
    path('trading-history/', trading_history, name='trading-history'),
    path('withdraw-funds/', withdraw_funds, name='withdraw-funds'),
    path('id-verification/', id_verification, name='id-verification'), 
    path('logout/', logout_view, name='logout'),
    path('account/upgrade', account_upgrade, name='account-upgrade'),
    # registration and login routes
    path('register/', register, name='register'),
    path('login/', login, name='login'),
    path('activation/resend/', views.resend_activation_link, name='resend-activation-link'),
    path('profile/create', create_profile, name='create-profile' ), 
    path('profile/edit', edit_profile, name='edit-profile' ),
    path('token-auth/', token_auth, name='token-auth'),
    path('account/change-password/',change_password, name='change-password' ),
    # validation routes
    path('validate/login', validate_login, name='validate-login'),
    path('validate/register', validate_registration, name='validate-registration'),

    # activate email link 
    path('activate/<slug:uidb64>/<slug:token>/', activate, name='activate'),
    path('activation/sent/', activation_sent, name='activation-sent'),
    
]
