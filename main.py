from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.utils import secure_filename
import os

from app.auth import *
from app.database import get_votings, add_voting, close_voting_by_id, get_voting_by_id

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
            session['user'] = email
            # TODO: store jwt token in session
            return redirect(url_for('voting_list'))
        flash('Invalid credentials')

    # GET
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register(): 
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        # register user
        if register_user(name, email, password):
            # TODO: generate key pair and store the public key in the database and download the private key to the user
            flash('Account created. Key pair generated.')
            return redirect(url_for('login'))
        flash('Email already registered')
    
    # GET
    return render_template('register.html')


@app.route('/voting_list', methods=['GET'])
def voting_list():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    return render_template('voting_list.html', votings=get_votings())


@app.route('/create_voting', methods=['GET', 'POST'])
def create_voting():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        voting = {
            'id': len(get_votings()), # TODO: better ID generation (in database)
            'name': request.form['voting_name'],
            'multiple_votes': 'multiple_votes' in request.form,
            'anonymous': 'anonymous' in request.form,
            'is_private': 'is_private' in request.form,
            'options': request.form.getlist('options[]'),
            'whitelist': request.form.getlist('emails[]'),  
            'votes': [],
            'status': 'Aberta',
            'creator': session['user']
        }
        add_voting(voting)
        return redirect(url_for('voting_list'))
    
    # GET
    return render_template('create_voting.html')


@app.route('/voting_info/<int:voting_id>', methods=['GET', 'POST'])
def voting_info(voting_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    voting = get_voting_by_id(voting_id)
    authorized = not voting['is_private'] or session['user'] in voting['whitelist']
    # TODO: verificar com o JWT se o usuário está autorizado a votar
    if not authorized:
        return render_template('voting_info.html', voting=voting, votes=[], authorized=False)

    if request.method == 'POST':
        choice = request.form['choice']
        file = request.files['private_key_file']
        filename = secure_filename(file.filename)
        # TODO: get the content of the private key file
        vote = {
            'voter': session['user'],
            'choice': choice,
            'valid': True  # TODO: verify validity of the vote using the private key
        }
        voting['votes'].append(vote)

    return render_template('voting_info.html', voting=voting, votes=voting['votes'], authorized=True)


@app.route('/voting_info/<int:voting_id>/close', methods=['POST'])
def close_voting(voting_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    # TODO: verificar com o JWT se o usuário é o criador do voto
    if session['user'] == get_voting_by_id(voting_id)['creator']:
        print(f"User {session['user']} is not authorized to close this voting {voting_id}")
        close_voting_by_id(voting_id)
        return redirect(url_for('voting_info', voting_id=voting_id))
    flash('You are not authorized to close this voting.')
    return redirect(url_for('voting_info', voting_id=voting_id))

if __name__ == '__main__':
    os.makedirs('uploads', exist_ok=True)
    app.run(debug=True)