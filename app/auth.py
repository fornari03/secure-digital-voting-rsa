from .repository import verify_user, add_user

def auth_user(login_username, login_password):
    # verify if the user's credentials are correct
    return verify_user(login_username, login_password)

def register_user(login_username, login_email, login_password, public_key):
    # add a new user if it does not exist
    return add_user(login_username, login_email, login_password, public_key)