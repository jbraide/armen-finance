from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth import login as auth_login

# import user settings
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required

# forms 
from .forms import RegistrationForm, LoginForm, ProfileForm, WithdrawalForm, VerificationDocumentForm, TokenForm, ChangePassword
from .forms import ArmenToArmenTransferForm, ResendLinkForm

# models
from .models import Balance, Signals, InvestedAmount, BTCbalance, Profile, DailyInvestments, VerificationDocument
from .models import CustomUser, Transaction, Registration, AuthToken, HashKey, HashedDetails
from django.db.models import Sum
from .models import AccountDetails

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

# create account 
from .create_ac_number import accountNumber

# data encryption
from .encryptdecrypt import EncryptDecryptKey

# django random string generator
from django.utils.crypto import get_random_string

from django.shortcuts import get_object_or_404

''' scheduler '''
from .celery.tasks import activation_link_send_task, send_token,  send_account_details_test

# encode data using jsonpickl
''' ref jsonpickle.readthedocs.io '''
import jsonpickle

''' views with no logic  '''

# homepage
def index(request):
    form = LoginForm()
    context = {
        'form': form
    }
    return render(request, 'main/index.html', context)

# About us page
def about(request):
    return render(request, 'main/about.html')


# contact page
def contact(request):
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
     
''' views with logic '''

'''             dashboard things             '''

# dashboard homepage / trading center
@login_required(login_url='main:login')
def dashboard(request):
    user = request.user
    # redirect only to the dashboard if the Token has been inserted.
    try:
        token = AuthToken.objects.get(
            user=user
        )
        return redirect('main:token-auth')

    except:          
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
    user_id = request.user.online_id
    print(user_id)
    # time.sleep(40)
    # get form details 
    if request.method == 'POST':
        form = ArmenToArmenTransferForm(request.POST)
        
        # check if a/c no exists
        if form.is_valid():
            # get form details 
            destination_account = form.cleaned_data.get('destination_account')
            transfer_amount = form.cleaned_data.get('amount')    
            transfer_description = form.cleaned_data.get('transfer_description')

            # if destination_account:
            
            ''' get account info from the account number ''' 
            # have to fix bug if account details does not exist
            try:
                # filtered_account = get_object_or_404(AccountDetails, account_number=destination_account)
                filtered_account = AccountDetails.objects.get(account_number= destination_account)
            except AccountDetails.DoesNotExist:
                messages.error(request, 'That account Number doesn\'t exist')
                return redirect('main:transfer-to-armen')

            # get the filtered account number
            receivers_account_number = filtered_account.account_number
            # get the filtered account numbers user
            receivers_online_id = filtered_account.user.online_id
            print(receivers_online_id)
            

            # if a/c no exists check for the balance left in the bank
            if destination_account == receivers_account_number:
                print('equal')
                # query the sum in the account balance 
                print(user_id)

                my_account_balance = Balance.objects.get(user=user_id).amount
                
                # if amount to transfer is smaller than what available in my account balance
                # then proceed
                if my_account_balance > transfer_amount:
                    # process the transfer
                    '''remove amount from my account''' 
                    # deduct transfered amount from account balance
                    # which gives a new balance for senders account
                    new_balance = my_account_balance - transfer_amount
                    new_balance = str(new_balance)

                    # update senders account information
                    Balance.objects.filter(user=user_id).update(amount=new_balance)

                    '''add transfer amount to receivers account '''
                    # get users balance
                    receivers_balance = Balance.objects.get(user=receivers_online_id).amount
                    # add new amount to recepients existing amount
                    receivers_new_balance = receivers_balance + transfer_amount
                    # update recepients accout with the new amount 
                    Balance.objects.filter(user=receivers_online_id).update(amount=receivers_new_balance)
                    messages.success(request, f'You have successfully transferred $ {transfer_amount} to { receivers_account_number } ')
                    return redirect('main:dashboard')
                else:
                # else the balance is too low
                    print('balance too low')
                    messages.error(request, f'Your account Balance is too low for the Transaction')
                    return redirect('main:transfer-to-armen')
            else:
            # a/c no does not exist
                messages.error(request, 'That Account Number Does Not exist')
                print('not found')

        # match an existing account number

        # 
    else:
        form = ArmenToArmenTransferForm()
    context = {
        'form': form
    }
    return render(request, 'main/transfer-to-armen.html', context)

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

# django serializer
from django.core import serializers
import time


def register(request):
    if request.method == "POST":
        # custom user  model
        User = get_user_model()

        # account and password generator 
        id = uuid4()
        password = get_random_string(14)
        # print(f'username {id}, password {password}')

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

            ''' create account number '''
            # run account number function
            account_number = accountNumber()

            AccountDetails.objects.create(
                user=user, 
                account_number=account_number
            )

            '''save the email'''
            Registration.objects.create(
                user=user, 
                email=email
            )

            ''' Encrypting online_id and password to be mailed to user '''
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
            # initialize password encryption  key 
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

            
            '''send activation link'''
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
            # serialize the online id with jsonpickle
            serialized_id = jsonpickle.encode(id)

            ''' send login details'''
            # encode the encryption key, online id and password to be sent to the scheduler 
            encode_encryption_key = jsonpickle.encode(init_key)
            encode_encrypted_online_id = jsonpickle.encode(online_id_encrypted)
            encode_encrypted_password = jsonpickle.encode(password_encrypted)
            encode_account_number = jsonpickle.encode(account_number)

            # send_account_details.delay(10, email, encode_encrypted_online_id, encode_encrypted_password, encode_account_number, encode_encryption_key )
            send_account_details_test.delay(3, email,serialized_id, password, account_number)
            activation_link_send_task.delay(12, serialized_id, subject, message, email)
            

            # redirect to activation link sent page
            return redirect('main:activation-sent')
    else:
        form = RegistrationForm()
    context = {
        'form': form
    }
    return render(request, 'main/register.html', context)

def resend_activation_link(request):
    # user = request.user
    # print(user)
    # return render(request, 'main/resend-link.html')
    if request.method == 'POST':
        # Registrations form
        form = ResendLinkForm(request.POST)
        if form.is_valid():
            # get email address from the form
            form_email = form.cleaned_data.get('email')
            print(form_email)
            Registration.objects.get(email=form_email)

            
        else:
            print('invalid FOrm')
            print(form.errors)

    else:
        form = ResendLinkForm()

    context = {
        'form': form
    }
    return render(request, 'main/resend-link.html', context)
    
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
        return redirect('main:login')

# login functionality
def login(request):
    if request.user.is_authenticated:
        # if the user is authenticated and has a token remove the token and logout of the session and relogin
        try:
            existing_token = AuthToken.objects.get(user=request.user.online_id)
            existing_token.delete()
            logout(request)
            return redirect('main:login')
        # if the user is authenticated and has no token then go to the dashboard
        except:
            return redirect('main:dashboard')
    else:
        User = get_user_model()
        if request.method == 'POST':
            # login POST request
            form = LoginForm(request.POST)
            # generate token key
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
                        ''' this should only happen when the user has put the token '''
                        auth_login(request, auth_user)

                        # get the current user by online id
                        current_usr =request.user.online_id

                        # get the user instance
                        user = User.objects.get(online_id=current_usr)

                        '''Token authentication and error handling''' 
                        
                        try:
                            # check if the user has a token then redirect to 
                            
                            user_token = AuthToken.objects.get(user=user)
                            user_email = Registration.objects.get(user=user)

                            # token and email
                            auth_token = user_token.token
                            email = user_email.email

                            print(auth_token)
                            time.sleep(30)

                            encode_token_login = jsonpickle.encode(auth_token)
                            encode_email = jsonpickle.encode(email)
                            
                        except:
                            ''' error handlin incase login happened and token was deleted '''                            
                            # if token does not exist  then create the token and redirect to token auth
                            create_token = AuthToken.objects.create(
                                user=user,
                                token=token_key
                            )

                            encode_token_login= jsonpickle.encode(token_key)

                            # send the authentication to the user
                            try:
                                # get the users email 
                                email = Registration.objects.get(
                                    user=user, 
                                ).email
                                encode_email = jsonpickle.encode(email)
                            except:
                                messages.error(request, 'You don\'t have your Email With Us.. Contact support@armenfinance.com for Help.')
                                print('user has no email')
                                return redirect('main:login')
                            

                        '''email the token to the user'''  
                        print(encode_token_login)                      

                        send_token.delay(3,encode_token_login,encode_email)

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
