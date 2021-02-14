from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm
from .models import Profile, Withdraw, Registration, AuthToken, ArmenToArmenTransfer,BookAppointment

''' Registration data '''

# registration 
class RegistrationForm(forms.ModelForm):    
    class Meta:
        model = Registration
        fields = ('email',)

class ResendLinkForm(forms.Form):
    email = forms.CharField(max_length=30,required=False)

# login form
class LoginForm(forms.Form):
    """user login form"""
    online_id = forms.UUIDField(required=True)
    password = forms.CharField(widget=forms.PasswordInput())

# token form
class TokenForm(forms.Form):
    token = forms.CharField(max_length=30, required=True)

# change password 
class ChangePassword(forms.Form):
    old_password = forms.CharField(widget=forms.PasswordInput())
    new_password = forms.CharField(widget=forms.PasswordInput())
    confirm_password = forms.CharField(widget=forms.PasswordInput())


# django countries & phone field
from django_countries.widgets import CountrySelectWidget
# from phone_field import PhoneField
class ProfileForm(forms.ModelForm):
    class Meta: 
        model = Profile
        fields = ('first_name', 'last_name','phone_number','street_address','city', 'state', 'postal_or_zip_code', 'profile_picture', 'country', 'select_plan')
        widgets = {
            'country': CountrySelectWidget(),
            # 'phone_number':
        }

class WithdrawalForm(forms.ModelForm):
    password = forms.CharField(max_length=30, widget=forms.PasswordInput)
     
    class Meta: 
        model = Withdraw
        fields = ('amount', 'password')

class ArmenToArmenTransferForm(forms.ModelForm):
    
    class Meta:
        model = ArmenToArmenTransfer
        fields = ('destination_account', 'amount', 'transfer_description')

class BookAppointmentForm(forms.ModelForm):
    meeting_time = forms.CharField(max_length=30)
    class Meta:
        model = BookAppointment
        fields = '__all__'
