from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.utils import secure_filename
import os

from app.auth import *
from app.repository import get_votings, add_voting, close_voting_by_id, get_voting_by_id, get_user_by_email, get_user_by_id, add_vote, list_votes_by_voting_id

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
        if register_user(name, email, password, public_key="mock_public_key"):
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
    
    votings_list = get_votings()
    # add votes count to each voting
    for voting in votings_list:
        voting['votes'] = list_votes_by_voting_id(voting['id'])
    
    return render_template('voting_list.html', votings=votings_list)


@app.route('/create_voting', methods=['GET', 'POST'])
def create_voting():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        voting = {
            'name': request.form['voting_name'],
            'multiple_votes': 'multiple_votes' in request.form,
            'anonymous': 'anonymous' in request.form,
            'is_private': 'is_private' in request.form,
            'options': request.form.getlist('options[]'),
            'whitelist': request.form.getlist('emails[]'),
            'status': 'Aberta',
            'creator': get_user_by_email(session['user'])['id']  # TODO: use JWT to get user info
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
    votes = list_votes_by_voting_id(voting_id)
    authorized = not voting['is_private'] or session['user'] in voting['whitelist']
    # TODO: verify with JWT if the user is authorized to vote
    if not authorized:
        return render_template('voting_info.html', voting=voting, votes=votes, authorized=False)

    # if the voting is not closed
    if voting['status'] == 'Aberta':
        if request.method == 'POST':
            choice = request.form['choice']
            file = request.files['private_key_file']
            filename = secure_filename(file.filename)
            # TODO: get the content of the private key file
            # TODO: hash the vote
            # TODO: sign the hashed vote with the private key
            # TODO: delete the private key variables for preventing memory leaks
            vote = {
                'voter': session['user'],
                'choice': choice,
            }
            # TODO: use the actual signed vote instead of this mock
            add_vote(vote.__hash__, vote['choice'], get_user_by_email(session['user'])['id'], voting['id'])
        return render_template('voting_info.html', voting=voting, votes=votes, authorized=True)
    
    # if the voting is closed, show the results
    for vote in votes:
        # TODO: verify if the vote is valid using the public key and testing the hash
        vote['valid'] = True  # mock validation
        vote['voter'] = get_user_by_id(vote['voter'])['email']
    return render_template('voting_info.html', voting=voting, votes=votes, authorized=True)




@app.route('/voting_info/<int:voting_id>/close', methods=['POST'])
def close_voting(voting_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    # TODO: verify if the user is the creator of the voting
    if get_user_by_email(session['user'])['id'] == get_voting_by_id(voting_id)['creator']:
        close_voting_by_id(voting_id)
        flash('Votação encerrada com sucesso.')
        return redirect(url_for('voting_info', voting_id=voting_id))
    
    flash('You are not authorized to close this voting.')
    return redirect(url_for('voting_info', voting_id=voting_id))



if __name__ == '__main__':
    app.run(debug=True)