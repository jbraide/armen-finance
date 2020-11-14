# celery imports
from celery.decorators import task
from celery.utils.log import get_task_logger
from celery import shared_task



# activation link task
from . import details_send
logger = get_task_logger(__name__)

# django mail 
from django.core.mail import send_mail

# import User model
from django.contrib.auth import get_user_model

# mport json pickle to decode the encoded information from the 
import jsonpickle

# duration importations
from time import sleep

@task(name='Activation Link send Task')
def activation_link_send_task(duration, user_id, subject, message, email):
    # decode the uuid to prevent the error 
    decoded_id = jsonpickle.decode(user_id)
    user_queried = get_user_model().objects.get(online_id=decoded_id)
    # set duration
    sleep(duration)
    # send activation link    
    details_send.send_activation_link(user_queried,subject, message, email)
    return (f'Email Sent to {decoded_id} ')

@task(name='Send Email Token')
def send_token(duration, token, email):
    # decode pickle to normal format with json pickle
    decoded_token = jsonpickle.decode(token)
    decoded_email = jsonpickle.decode(email)
    # set scheduler sleep function
    sleep(duration)
    # mail the token to the user
    send_mail('Login token', decoded_token, 'support@armenfinance.com', [decoded_email,])
    return ('token sent')

# @task(name='Account Details(online_id, password, account_number')
# def send_account_details(duration,email, online_id, password, account_number, encryption_token):
#     # decode details with json pickle 
#     decode_online_id = jsonpickle.decode(online_id)
#     decode_password = jsonpickle.decode(password)
#     decode_account_number = jsonpickle.decode(account_number)

#     # get the pasword & online token encryption Key
#     decode_key = jsonpickle.decode(encryption_token)
#     # decrypt the password and online id message 
#     decrypt_online_id = decode_key.decrypt(decode_online_id).decode()
#     decrypt_password = decode_key.decrypt(decode_password).decode()
#     print(decrypt_online_id, decrypt_password)

#     # set the scheduler sleep function

#     # mail the details to the users email
#     return 'DOne'


@task(name='Account Details(online_id, password, account_number')
def send_account_details_test(duration,email, online_id, password, account_number):
    # decode online_id 
    decode_online_id  = jsonpickle.decode(online_id)
    # # decode details with json pickle 
    # decode_online_id = jsonpickle.decode(online_id)
    # decode_password = jsonpickle.decode(password)
    # decode_account_number = jsonpickle.decode(account_number)

    # # get the pasword & online token encryption Key
    # decode_key = jsonpickle.decode(encryption_token)
    # # decrypt the password and online id message 
    # decrypt_online_id = decode_key.decrypt(decode_online_id).decode()
    # decrypt_password = decode_key.decrypt(decode_password).decode()
    # print(decrypt_online_id, decrypt_password)

    # set the scheduler sleep function
    sleep(duration)

    # mail the details to the users email
    mail_message = f'Find below Your login information Online Id:{decode_online_id}, Password: {password}, Account Number:; {account_number}' 
    send_mail('Account Login details', mail_message,'support@armenfinance.com' ,[email,] )
    return 'DOne'
