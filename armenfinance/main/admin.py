from django.contrib import admin
from .models import Profile, Balance, Transaction

'''
    custom user admin fieldset
'''
"""Integrate with admin module."""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin
from django.utils.translation import ugettext_lazy as _

from .models import CustomUser, Registration, AuthToken, AccountDetails, Savings, Investment, Retirement, BookAppointment
from .forms  import RegistrationForm


@admin.register(CustomUser)
class CustomUserAdmin(DjangoUserAdmin):
    """Define admin model for custom User model with no email field."""

    DjangoUserAdmin.fieldsets = (
        (None, {'fields': ('online_id', 'password')}),
        (_('Personal info'), {'fields': ()}),
        (_('Permissions'), {'fields': ('is_active', 'is_staff', 'is_superuser',
                                       'groups', 'user_permissions')}),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
    )
    add_form = RegistrationForm
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('online_id', 'password1', 'password2'),
        }),
    )
    # add_form = RegistrationForm
    # CUSTOM USER 1
    list_display = ('online_id',)
    search_fields = ('online_id',)
    ordering = ('online_id',)

    # CUSTOM USER 2
    # list_display = ('email', 'first_name', 'last_name', 'is_staff')
    # search_fields = ('email', 'first_name', 'last_name')
    # ordering = ('email',)


''' 
    Other fields
'''

# profile
@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ['first_name', ]

@admin.register(Balance)
class BalanceAdmin(admin.ModelAdmin):
    list_display = ['user', 'amount']


# transaction history
@admin.register(Transaction)
class TransactionAdmin(admin.ModelAdmin):
    list_display = ['date',]

# registration 
@admin.register(Registration)
class RegistrationAdmin(admin.ModelAdmin):
    list_display = ['user', 'email']

# login token
@admin.register(AuthToken)
class AuthTokenAdmin(admin.ModelAdmin):
    list_display = ['user', 'token']


# account number 
@admin.register(AccountDetails)
class AccountDetailsAdmin(admin.ModelAdmin):
    list_display = ['user', 'account_number']

''' savings / investment / Retirement'''
@admin.register(Savings)
class SavingsAdmin(admin.ModelAdmin):
    list_display = ['user', 'balance' ]

@admin.register(Retirement)
class RetirementAdmin(admin.ModelAdmin):
    list_display = ['user', 'balance' ]

@admin.register(Investment)
class InvestmentAdmin(admin.ModelAdmin):
    list_display = ['user', 'balance' ]

@admin.register(BookAppointment)
class BookAppointmentAdmin(admin.ModelAdmin):
    list_display= ['full_name',]
    
