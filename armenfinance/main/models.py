from django.db import models
from django.contrib.auth.models import User, AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db.models.signals import post_save
from django.dispatch import receiver
from django_countries.fields import CountryField
from django.utils.translation import ugettext_lazy as _

''' custom user stuff '''
# timezone for custom user model
from django.utils import timezone

# importing uuid for custom username ids
import uuid

# use this instead of User
from django.contrib.auth import settings
# import send mail for custom user
from django.core.mail import send_mail

''' 
for phone field
'''
from phonenumber_field.modelfields import PhoneNumberField



'''
    creating custom user
'''
# CUSTOM user first design

class CustomUserManager(BaseUserManager):
    ''' custom user model manager wher email is the unique identifiers for authentication instead of usernames '''

    def _create_user(self, online_id, password,is_staff, is_superuser, **extra_fields):
        ''' create and save a User with the given email and password '''
        if not online_id:
            raise ValueError(_('The email must be set'))
        now = timezone.now()
        # email = self.normalize_email(email)
        user = self.model(
            # email=email,
            online_id=online_id,
            is_staff=is_staff,
            is_active=True,
            is_superuser=is_superuser,
            last_login=now,
            **extra_fields)

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, online_id, password, **extra_fields):
        return self._create_user(online_id, password, False, False, **extra_fields)
    def create_superuser(self, online_id, password, **extra_fields):
        user = self._create_user(online_id, password, True, True, **extra_fields)
        return user
    

class CustomUser(AbstractBaseUser, PermissionsMixin):
    # user_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    online_id = models.UUIDField(primary_key=True,default=uuid.uuid4)
    # email = models.EmailField(_('email address'), unique=True)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    date_joined = models.DateTimeField(default=timezone.now)

    USERNAME_FIELD = 'online_id'
    REQUIRED_FIELDS = []

    objects = CustomUserManager()

    def __str__(self):
        return str(self.online_id)
    def user_id(self):
        return self.id.__str__()
    def email_user(self, subject, message, email, from_email=None ):
        send_mail(
            subject, 
            '', 
            from_email, 
            [email,], 
            html_message=message,
        )
"""
    Registration  models
    
"""
class Registration(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    email = models.EmailField(max_length=254, unique=True)

# authentication token
class AuthToken(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    token = models.CharField(max_length=30, unique=True)

''' investment retirment & savings '''

class Transaction(models.Model):
    types = (
        ('Debit', 'Debit'), 
        ('Credit', 'Credit'),
    )
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    transaction_id = models.UUIDField(default=uuid.uuid4)
    date = models.DateTimeField(auto_now_add=True)
    transaction_type = models.CharField(max_length=20,choices=types)
    amount = models.IntegerField()
    balance = models.IntegerField()




class Savings(models.Model):
    status = (
        ('Increased', 'Increased'), 
        ('Decreased', 'Decreased'),
    )
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    percentage = models.PositiveIntegerField()
    percentage_status = models.CharField(max_length=20, choices=status)
    duration = models.IntegerField()
    balance = models.IntegerField()

class Investment(models.Model):
    status = (
        ('Increased', 'Increased'), 
        ('Decreased', 'Decreased'),
    )
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    percentage = models.PositiveIntegerField()
    percentage_status = models.CharField(max_length=20, choices=status)
    duration = models.IntegerField()
    balance = models.IntegerField()

class Retirement(models.Model):
    status = (
        ('Increased', 'Increased'), 
        ('Decreased', 'Decreased'),
    )
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    percentage = models.PositiveIntegerField()
    percentage_status = models.CharField(max_length=20, choices=status)
    duration = models.IntegerField()
    balance = models.IntegerField()



# profile

plans = (
    ('Checking Accounts', 'Checking Accounts'),
    ('Invest', 'Invest'),
    ('Home Lending', 'Home Lending'),
    ('Savings', 'Savings'),
)
class Profile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='profile')
    first_name = models.CharField(max_length=23, default='', blank=True)
    last_name = models.CharField(max_length=23, default='', blank=True)
    phone_number = PhoneNumberField(blank=True, help_text='Contact Phone Number')
    street_address = models.CharField(max_length=150, default='', blank=True)
    city =  models.CharField(max_length = 100, default='', blank=True)
    state = models.CharField(max_length=30, default= '', blank=True)
    postal_or_zip_code = models.CharField(max_length=6, blank=True)
    profile_picture = models.ImageField(upload_to='profile_pictures/', blank=True, null=True)
    country = CountryField(blank_label='(select country)', blank=True, null=True)
    select_plan = models.CharField(max_length=40, choices=plans)
    def __str__(self):
        return self.first_name
        
@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)
        Balance.objects.create(
            user=instance,
            amount=0
        )
        Savings.objects.create(
            user=instance, 
            percentage = 0,
            percentage_status='',
            duration=0,
            balance=0
        )
        Investment.objects.create(
            user=instance, 
            percentage = 0,
            percentage_status='',
            duration=0,
            balance=0
        )
        Retirement.objects.create(
            user=instance, 
            percentage = 0,
            percentage_status='',
            duration=0,
            balance=0
        )



@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def save_user_profile(sender, instance, **kwargs):
    instance.profile.save()

'''
    Dashboard  models
'''

''' account number + transfer models '''
from django.core.validators import MaxValueValidator
class AccountDetails(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    account_number = models.CharField(max_length=11, default='')

class ArmenToArmenTransfer(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    destination_account = models.CharField(max_length=11, default='')
    amount = models.PositiveIntegerField()
    transfer_description = models.CharField(max_length=400, default='')

class ArmenToForeignAccountTransfer(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    purpose = models.CharField(max_length=40, default='')
    country = CountryField(blank_label='(select country)', blank=True, null=True)
    beneficiary_name = models.CharField(max_length=100)
    beneficiary_account = models.CharField(max_length=22)
    beneficiary_address = models.CharField(max_length=300)
    beneficiary_branch_address = models.CharField(max_length=300)
    city = models.CharField(max_length=100)
    amount = models.PositiveIntegerField()
    routing_number = models.PositiveIntegerField()
    transfer_description = models.CharField(max_length=400, default='')



# balance
class Balance(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    amount = models.PositiveIntegerField()


# withdrawal
class Withdraw(models.Model):
    amount = models.DecimalField(max_digits=10, decimal_places=2)    
    password = models.CharField(max_length=30, default = '')


class BookAppointment(models.Model):
    choose = (
        ('Support', 'Support'),
        ('Sales', 'Sales'),
        ('Abuse', 'Abuse'),
        ('Billing', 'Billing'),
    )
    full_name = models.CharField(max_length=100, default='', help_text='Enter Full Name', blank=False)
    phone_number = PhoneNumberField(blank=True, help_text='Contact Phone Number')
    email = models.EmailField(max_length=50, blank=False)
    speak_with = models.CharField(choices=choose, max_length=30)
    reason_for_meeting = models.TextField()
    meeting_time = models.CharField(max_length=30)

# # verification documents
# class VerificationDocument(models.Model):
#     user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
#     document_type = models.CharField(max_length=30)
#     front_document = models.FileField(upload_to='doc/front_page/', blank=False, null=False)
#     back_document = models.FileField(upload_to='doc/back_page/', blank=False, null=False)
#     verified = models.BooleanField(default=False, blank=True)


class ForeignTransferTransaction(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    transaction_id = models.UUIDField(default=uuid.uuid4)
    foreign_tf = models.ForeignKey(ArmenToForeignAccountTransfer, on_delete=models.CASCADE)
    date = models.DateTimeField()
    transaction_type = models.CharField(max_length=40, default='Foreign Transfer')
    amount = models.PositiveIntegerField()
    balance = models.PositiveIntegerField()
    percentage_complete = models.PositiveIntegerField(null=True,blank=True, default=0)