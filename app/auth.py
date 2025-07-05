from .database import verify_user, add_user

def auth_user(login_username, login_password):
    # verifica se as credenciais do usuário estão corretas
    return verify_user(login_username, login_password)

def register_user(login_username, login_email, login_password):
    # adiciona o novo usuário caso ele não exista
    return add_user(login_username, login_email, login_password)