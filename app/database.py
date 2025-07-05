# TODO: refactor this file to use a proper database

users = {}
votings = []

def verify_user(email, password):
    user = users.get(email)
    if user and user['password'] == password:
        return True
    return False

def add_user(name, email, password):
    if email in users:
        return False  # user already exists
    users[email] = {
        'name': name,
        'password': password,
        'public_key': f"PUBLIC_KEY_{email}" # TODO: use actual key
    }
    return True

def get_votings():
    return votings

def add_voting(voting):
    votings.append(voting)

def get_voting_by_id(voting_id):
    return votings[voting_id]

def close_voting_by_id(voting_id):
    votings[voting_id]['status'] = 'Encerrada'