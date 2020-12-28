from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth import login as auth_login

# import user settings
from django.contrib.auth import get_user_model

from django.contrib.auth.decorators import login_required

from .forms import RegistrationForm, LoginForm, ProfileForm, WithdrawalForm, VerificationDocumentForm, TokenForm, ChangePassword

# models
from .models import Balance, Signals, InvestedAmount, BTCbalance, Profile, DailyInvestments, VerificationDocument
from .models import CustomUser, Transaction, Registration, AuthToken, HashKey, HashedDetails
from django.db.models import Sum

# password reset 
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm

# time, dateteime
# import time
import datetime

# email activation part
from django.http import HttpResponse
from django.core.mail import send_mail
from django.contrib import messages
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.template.loader import render_to_string
from .token import account_activation_token

# data encryption
from .encryptdecrypt import EncryptDecryptKey

# django random string generator
from django.utils.crypto import get_random_string



''' views with no logic  '''

# homepage
def index(request):
    return render(request, 'main/index.html')


def index2(request):
    form = LoginForm()
    context = {
        'form': form
    }
    return render(request, 'main/index-2.html', context)

# About us page
def about(request):
    return render(request, 'main/about.html')
import json
# contact page
def contact(request):
    id = request.user.online_id

    # change uuid to string
    id = str(id)
    
    # user_id = json.dumps(id)    
    print(str(id))

    # print(str(user_id).decode('utf-8'))
    send_password(id)
    # send_password()
    return render(request, 'main/contact.html')

# Privacy Policy
def privacy_policy(request):
    return render(request, 'main/privacy-policy.html')

# payment policy
def payment_policy(request):
    return render(request, 'main/payment-policy.html')

# terms and conditions
def terms_and_condition(request):
    return render(request,'main/terms-and-conditions.html')

# activation sent 
def activation_sent(request):
    return render(request, 'main/activation-sent.html')

def create_card(request):
    return render(request, 'main/create-card.html')

def update_credit_score(request):
    return render(request, 'main/update-credit-score.html')
     
''' views with logic '''

'''             dashboard things             '''

# dashboard homepage / trading center
@login_required(login_url='login')
def dashboard(request):
    user = request.user

    # dashboard info from database
    balance = Balance.objects.filter(user=user).aggregate(amount=Sum('amount'))
    signals_amount = Signals.objects.filter(user=user).aggregate(amount=Sum('amount'))
    invested = InvestedAmount.objects.filter(user=user).aggregate(amount=Sum('amount'))
    btc_balance = BTCbalance.objects.filter(user=user).aggregate(amount=Sum('amount'))
    daily_investments = DailyInvestments.objects.filter(user=user).aggregate(amount=Sum('amount'))
    transaction_details = Transaction.objects.filter(user=user)

    # id verification logic
    if request.method == 'POST':
        verification_form = VerificationDocumentForm(request.POST,request.FILES)
        if verification_form.is_valid():
            # verification model 
            ver_model = VerificationDocument
            
            # collect form data
            document_type = verification_form.cleaned_data.get('document_type')
            front_document = verification_form.cleaned_data.get('front_document')
            back_document = verification_form.cleaned_data.get('back_document')

            # pass form data to the model
            ver_model.objects.create(
                user = request.user,
                document_type=document_type,
                front_document=front_document,
                back_document=back_document
            )
            return redirect('main:dashboard')  
        else:
            print(verification_form.errors)
    else:
        verification_form = VerificationDocumentForm()

    context = {
        'balance': balance, 
        'signals': signals_amount, 
        'invested': invested,
        'btc_balance': btc_balance,
        'daily_investments': daily_investments, 
        'verification_form': verification_form, 
        'transaction':transaction_details
    }
    return render(request, 'main/dashboard.html', context)

# transfer to armen account
@login_required(login_url='main:login')
def transfer_to_armen(request):
    return render(request, 'main/transfer-to-armen.html')

# transfer to foreign account
@login_required(login_url='main:login')
def transfer_to_foreign_account(request):
    return render(request, 'main/transfer-foreign-account.html')

# fund account
from django.contrib import messages
@login_required(login_url='/accounts/login')
def fund_account(request):
    return render(request, 'main/fund-account.html')

# transactions view 
def trading_history(request):
    return render(request, 'main/trading-history.html')

# withdrawal fn
from django.contrib.auth.hashers import check_password

@login_required(login_url='/accounts/login')
def withdraw_funds(request): 
    user = request.user
    balance = Balance.objects.filter(user=user).aggregate(amount=Sum('amount'))
    form = WithdrawalForm(request.POST)
    userPassword = request.user.password
    if request.method == 'POST':
        messages.success(request, 'Withdrawal pending please wait a shortwhile')
        
        
        if form.is_valid():
            form.save(commit=False)
            password = form.cleaned_data.get('password')

            match_password = check_password(password, userPassword)
            # messages.success(request, 'Withdraw Successful')
            
            if match_password:
                print('passwords matched')
                form.save()
                return redirect('main:dashboard')
            else:
                print('problem with matching password')
        else: 
            print('error')
    else:
        form = WithdrawalForm()

    context = {
        'form': form,
        'balance': balance,
    }

    return render(request, 'main/withdraw-funds.html', context )

# document verification
from django.contrib.auth import get_user_model
from .models import CustomUser

@login_required(login_url='login')
def id_verification(request):
    if request.method == 'POST':
        verification_form = VerificationDocumentForm(request.POST,request.FILES)
        if verification_form.is_valid():
            # verification model
            ver_model = VerificationDocument

            # collect form data
            document_type = verification_form.cleaned_data.get('document_type')
            front_document = verification_form.cleaned_data.get('front_document')
            back_document = verification_form.cleaned_data.get('back_document')
            ver_model.objects.create(
                user = request.user,
                document_type=document_type,
                front_document=front_document,
                back_document=back_document
            )
            return redirect('main:dashboard')
        else:
            print(verification_form.errors)
    else:
        verification_form = VerificationDocumentForm()

    context = {
        'verification_form': verification_form
    }
    return render(request, 'main/id-verification.html', context)

def account_upgrade(request):
    return render(request, 'main/account-upgrade.html')


''' account setup '''
'''       profile / registration / logout            '''


# custom registration route
from uuid import uuid4
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password


# test time
import time

def register(request):
    if request.method == "POST":
        # custom user  model
        User = get_user_model()

        # account and password generator 
        id = uuid4()
        password = get_random_string(14)
        print(f'username {id}, password {password}')

        form = RegistrationForm(request.POST)
        if form.is_valid():
            # get email from the form
            email = form.cleaned_data.get('email')           

            # create user with details
            User.objects.create_user(
                id,
                password
            )
            user_login = authenticate(request, online_id=id, password=password)

            # query for the user
            user = User.objects.get(online_id=id)

            # deactivate the user
            user.is_active = False

            # save the user instance
            user.save()

            # instantiate the encryptdecrypt class
            encrypt_decrypt = EncryptDecryptKey()
            # generate the key
            key = encrypt_decrypt.encryptionKey()
            # save encrypted Key to the db of the user
            HashKey.objects.create(
                user=user,
                email=email,
                key=key
            )
            # initialize key 
            init_key = encrypt_decrypt.preapare_encrypt_data(key)
            # encrypt the online_id && password
            online_id_encrypted = init_key.encrypt(str(id).encode())
            password_encrypted = init_key.encrypt(password.encode())

            # save encrypted online_id and password  to the  Database of the user
            HashedDetails.objects.create(
                user=user, 
                email=email,
                online_id=online_id_encrypted,
                password=password_encrypted
            )

            # save the email
            Registration.objects.create(
                user=user, 
                email=email
            )
            # send activation link
            current_site = get_current_site(request)
            subject = 'Activate Your Armen Finance Account'
            message = render_to_string(
                'main/activation-link.html', {
                    'user': user, 
                    'domain': current_site.domain, 
                    'uid': urlsafe_base64_encode(force_bytes(user.pk)), 
                    'token': account_activation_token.make_token(user),
                }
            )

            user.email_user (subject, message, email)
            # redirect to activation link sent page
            return redirect('main:activation-sent')
    else:
        form = RegistrationForm()
    context = {
        'form': form
    }
    return render(request, 'main/register.html', context)


# activate account when the email link is clicked
def activate(request, uidb64, token):
    User = get_user_model()
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        auth_login(request, user)
        return redirect('main:create-profile')

# login functionality
def login(request):
    User = get_user_model()
    if request.method == 'POST':
        # login POST request
        form = LoginForm(request.POST)
        token_key = get_random_string(30)
        if form.is_valid():
            # get login form data form 
            online_id = form.cleaned_data.get('online_id')
            password = form.cleaned_data.get('password')

            # authenticate user
            auth_user = authenticate(online_id=online_id,password=password)
            if auth_user is not None:
                if auth_user.is_active:
                    # login the user
                    auth_login(request, auth_user)

                    # get the current user by online id
                    current_usr =request.user.online_id

                    # get the user instance
                    user = User.objects.get(online_id=current_usr)


                    # time.sleep(5)
                    # generate token 
                    AuthToken.objects.create(
                       user=user,
                       token=token_key
                    )
                    
                    # email the token to The user

                    # redirect 
                    return redirect('main:token-auth')
                else:
                    print('user is inactive')
            else:
                print('invalid Username/password')
            
        else:
            return render(request, 'main/login.html', {
                'form': form
            })
    else:
        form = LoginForm()
    context = {
        'form': form
    }
    return render(request, 'main/login.html', context)

# Login token authentication
def token_auth(request):
    User = get_user_model()
    if request.method == 'POST':
        Auth = AuthToken
        form = TokenForm(request.POST)
        if form.is_valid():
            # token from the form
            token = form.cleaned_data.get('token')

            # get the logged in user session
            user = User.objects.get(online_id=request.user.online_id)

            # token from database
            # user_token = AuthToken.objects.get(user=user)

            try:
                user_token = Auth.objects.get(user=user)
            except(Auth.DoesNotExist):
                Auth = None       
                #  display error message ( token does not exist)
                messages.error(request,'Token Does Not Exist')
                return render(request, 'main/token-auth.html', {
                    'form': form
                })    

            if token == user_token.token:
                # remove token from database
                AuthToken.objects.filter(user=user).delete()
                print('token deleted')
                # redirect to dashboard
                return redirect('main:dashboard')
            else: 
                print('wrong token')

            # print(user, user_token.token)
        else:
            print('invalid form ')
    else:
        form = TokenForm()
    context = {
        'form': form
    }
        

    # print(request.user.online_id)
    return render(request,'main/token-auth.html', context)

# create profile with the registration data 
def create_profile(request):
    # POST request form logic
    if request.method == 'POST':
        # request user instance
        profile_form = ProfileForm(request.POST,instance=request.user, files=request.FILES)
        if profile_form.is_valid():
            # gather profile form data
            first_name = profile_form.cleaned_data.get('first_name')
            last_name = profile_form.cleaned_data.get('last_name')
            phone_number = profile_form.cleaned_data.get('phone_number')
            street_address = profile_form.cleaned_data.get('street_address')
            city = profile_form.cleaned_data.get('city')
            state = profile_form.cleaned_data.get('state')
            postal_or_zip_code = profile_form.cleaned_data.get('postal_or_zip_code')
            profile_picture = profile_form.cleaned_data.get('profile_picture')
            country = profile_form.cleaned_data.get('country')
            select_plan = profile_form.cleaned_data.get('select_plan')
            
            '''fetch profile of currently registered and logged in user first'''
            # request user
            user = request.user
            # filter by UUID and match the user that has been created from the registration
            profile_user = Profile.objects.filter(user_id=user.online_id)

            # update the users profile with the required form data
            profile_user.update(
                first_name = first_name,
                last_name = last_name,
                phone_number = phone_number, 
                street_address=street_address,
                city = city,
                state = state, 
                postal_or_zip_code = postal_or_zip_code,
                profile_picture = profile_picture,
                country  = country,
                select_plan = select_plan 
            )

            # save the profile data to the form model 
            profile_form.save()

            # redirect to the dashboard
            return redirect('main:dashboard')

        else:
            # print profile form errors to the console
            print(profile_form.errors)
    else:
        # GET profile form
        profile_form = ProfileForm()
    context = {
        'profile_form': profile_form
    }
    return render(request, 'main/create-profile.html', context)

def edit_profile(request):
    return render(request, 'main/edit-profile.html')

# update profile 
from django.contrib.auth.hashers import check_password
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm

def change_password(request):
    userPassword = request.user.password
    if request.method == 'POST':
        change_form = ChangePassword(request.POST)
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()            
            update_session_auth_hash(request, user)
            return redirect('main:dashboard')
        else:
            print('form error ')
    else:
        change_form = ChangePassword()
        form = PasswordChangeForm(request.user)
    
    context = {
        'change_form': change_form,
        'form': form
    }

    return render(request, 'main/change-password.html', context)

# logout route
@login_required(login_url='/accounts/login')
def logout_view(request):
    # logout user
    logout(request)
    return redirect('main:index')

from django.contrib.auth import get_user_model
from django.http import JsonResponse


# ajax form validation
def validate_login(request):
    email = request.GET.get('email', None)
    User = get_user_model()
    data = {
        'is_taken': User.objects.filter(email__iexact=email).exists()
    }
    return JsonResponse(data)


def validate_registration(request):
    email = request.GET.get('email', None)
    password = request.GET.get('password1', None)
    User = get_user_model()
    data = {
        'is_user': User.objects.filter(email__iexact=email).exists(),
        'password': password,
    }
    return JsonResponse(data)


''' error messages ''' 
def handler404(request):
    return render(request, 'error_404.html', status=404)


# background task for sending password/username data
from background_task import background
from django.contrib.auth import get_user_model

@background(schedule=60*3)
def send_password(online_id):
    # get the user
    User = get_user_model()
    user = User.objects.get(pk=online_id)

    # query for the encryption key
    db_hask_key = HashKey.objects.filter(user=user)
    print(db_hask_key.key.decode('utf-8'))
    # get the hashed password and online_id of the user

    # dehash them

    # send to the user
# user_id = request.user.online_id
# send_password(user_id)
