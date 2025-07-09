from flask import Flask, render_template, request, redirect, url_for, session, flash, Response

from app.auth import *
from app.repository import get_votings, add_voting, close_voting_by_id, get_voting_by_id, get_user_by_email, get_user_by_id, add_vote, list_votes_by_voting_id, add_jti_to_blacklist, is_blacklisted
from app.crypto import generate_rsa_key_pair, sign_vote, verify_signature, generate_jwt, verify_jwt, get_jti

app = Flask(__name__)
app.secret_key = 'testsecretkey'


@app.route('/')
def home():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if auth_user(email, password):
            response = redirect(url_for('voting_list'))
            token = generate_jwt(email)
            response.set_cookie('jwt', token, httponly=True, secure=True)
            return response
        flash('Credenciais inválidas.', 'warning')

    # GET
    return render_template('login.html')


@app.route('/logout')
def logout():
    token = request.cookies.get('jwt')
    if not token:
        return redirect(url_for('login'))
    if not verify_jwt(token):
        flash('Sessão expirada. Por favor, faça login novamente.', 'warning')
        return redirect(url_for('login'))
    
    session.clear()
    token = request.cookies.get('jwt')
    jti = get_jti(token)
    if jti is not None:
        add_jti_to_blacklist(jti)
    response = redirect(url_for('login'))
    response.delete_cookie('jwt')
    flash('Você saiu da conta com sucesso.', 'info')
    return response


@app.route('/register', methods=['GET', 'POST'])
def register(): 
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        # register user
        if not get_user_by_email(email):
            private_key, public_key = generate_rsa_key_pair()
            register_user(name, email, password, public_key)
            session['private_key'] = private_key.decode('utf-8')
            flash('Conta criada com sucesso!', 'success')
            return redirect(url_for('download_private_key'))

        flash('Email já cadastrado.', 'danger')
    
    # GET
    return render_template('register.html') 


@app.route('/download_private_key', methods=['GET'])
def download_private_key():
    if 'private_key' not in session:
        return redirect(url_for('login'))
    
    private_key = session.pop('private_key')

    return Response(
        private_key,
        mimetype='application/octet-stream',
        headers={
            'Content-Disposition': f'attachment; filename=private_key.pem'
        }
    )


@app.route('/voting_list', methods=['GET'])
def voting_list():
    token = request.cookies.get('jwt')
    if not token:
        return redirect(url_for('login'))
    if not verify_jwt(token):
        flash('Sessão expirada. Por favor, faça login novamente.', 'warning')
        return redirect(url_for('login'))

    
    votings_list = get_votings()
    # add votes count to each voting
    for voting in votings_list:
        voting['votes'] = list_votes_by_voting_id(voting['id'])
    
    return render_template('voting_list.html', votings=votings_list)


@app.route('/create_voting', methods=['GET', 'POST'])
def create_voting():
    token = request.cookies.get('jwt')
    if not token:
        return redirect(url_for('login'))
    if not verify_jwt(token):
        flash('Sessão expirada. Por favor, faça login novamente.', 'warning')
        return redirect(url_for('login'))
        
    payload = verify_jwt(token)
    user_id = get_user_by_email(payload['sub'])['id']

    if request.method == 'POST':
        voting = {
            'name': request.form['voting_name'],
            'multiple_votes': 'multiple_votes' in request.form,
            'anonymous': 'anonymous' in request.form,
            'is_private': 'is_private' in request.form,
            'options': request.form.getlist('options[]'),
            'whitelist': [payload['sub']] + request.form.getlist('emails[]'),
            'status': 'Aberta',
            'creator': user_id
        }
        add_voting(voting)
        flash('Votação criada com sucesso!', 'success')
        return redirect(url_for('voting_list'))
    
    # GET
    return render_template('create_voting.html')


@app.route('/voting_info/<int:voting_id>', methods=['GET', 'POST'])
def voting_info(voting_id):
    token = request.cookies.get('jwt')
    if not token:
        return redirect(url_for('login'))
    if not verify_jwt(token):
        flash('Sessão expirada. Por favor, faça login novamente.', 'warning')
        return redirect(url_for('login'))
    
    payload = verify_jwt(token)
    voting = get_voting_by_id(voting_id)
    votes = list_votes_by_voting_id(voting_id)
    voting['options'] = voting['options'].split(',') # HACK: it's a string in the database, so we need to convert it to a list
    authorized = not voting['is_private'] or payload['sub'] in voting['whitelist']
    if not authorized:
        flash('Você não está autorizado a ver essa votação privada.', 'warning')
        return render_template('voting_info.html', voting=voting, votes=votes, authorized=False)

    # if the voting is not closed
    if voting['status'] == 'Aberta':
        if request.method == 'POST':
            choice = request.form['choice']
            file = request.files['private_key_file']

            # get the content of the private key file as bytes
            private_key_content = file.read()

            user_id = get_user_by_email(payload['sub'])['id']
            vote_data = {
                'voter': user_id,
                'choice': choice,
                'voting': voting_id
            }
            signed_vote = sign_vote(private_key_content, str(vote_data))
            
            del private_key_content  # remove private key content from memory
            del file  # remove file from memory

            if signed_vote == False:
                flash('Formato inválido da chave privada.', 'danger')
            else:
                add_vote(signed_vote, vote_data['choice'], user_id, voting['id'])
        return render_template('voting_info.html', voting=voting, votes=votes, authorized=True)
    
    # if the voting is closed, show the results
    users = set()
    votes = votes[::-1]  # reverse the votes to show the latest votes first
    for vote in votes:
        # verify if the vote is valid with verify_signature
        user_id = vote['voter']
        public_key = get_user_by_id(user_id)['public_key']
        vote_data = {
            'voter': user_id,
            'choice': vote['choice'],
            'voting': vote['voting']
        }

        vote['valid'] = verify_signature(vote['signed_vote'], public_key, str(vote_data))
        vote['voter'] = get_user_by_id(vote['voter'])['email']
        if vote['valid'] and not voting['multiple_votes']:
            if user_id not in users:
                users.add(user_id)
            else:
                vote['valid'] = "i" # ignored, user already voted

    return render_template('voting_info.html', voting=voting, votes=votes[::-1], authorized=True)


@app.route('/voting_info/<int:voting_id>/close', methods=['POST'])
def close_voting(voting_id):
    token = request.cookies.get('jwt')
    if not token:
        return redirect(url_for('login'))
    if not verify_jwt(token):
        flash('Sessão expirada. Por favor, faça login novamente.', 'warning')
        return redirect(url_for('login'))
    
    payload = verify_jwt(token)
    user_id = get_user_by_email(payload['sub'])['id']
    if user_id == get_voting_by_id(voting_id)['creator']:
        close_voting_by_id(voting_id)
        flash('Votação encerrada com sucesso.', 'success')
        return redirect(url_for('voting_info', voting_id=voting_id))
    
    flash('Você não tem permissão para encerrar esta votação.', 'danger')
    return redirect(url_for('voting_info', voting_id=voting_id))


if __name__ == '__main__':
    app.run(ssl_context=("cert.pem", "key.pem"), debug=True)