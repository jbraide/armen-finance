def send_activation_link(user_queried, subject, message, email):
    user = user_queried
    user.email_user(subject, message, email)

