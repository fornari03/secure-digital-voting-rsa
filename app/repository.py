import sqlite3, os, bcrypt


USERS_DATABASE = 'users.db'
VOTINGS_DATABASE = 'votings.db'
VOTES_DATABASE = 'votes.db'
BLACKLIST_DATABASE = 'blacklist.db'


# create the database and tables if they do not exist
def init_db():
    with sqlite3.connect(USERS_DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            public_key TEXT NOT NULL
        )
        ''')
        conn.commit()
    
    with sqlite3.connect(VOTINGS_DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS votings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            multiple_votes BOOLEAN NOT NULL,
            anonymous BOOLEAN NOT NULL,
            is_private BOOLEAN NOT NULL,
            options TEXT NOT NULL,
            whitelist TEXT,
            status TEXT NOT NULL DEFAULT 'Aberta',
            creator INTEGER NOT NULL,
            FOREIGN KEY (creator) REFERENCES users(id)
        )
        ''')
        conn.commit()

    with sqlite3.connect(VOTES_DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS votes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            signed_vote TEXT,
            choice TEXT NOT NULL,
            voter INTEGER NOT NULL,
            voting INTEGER NOT NULL,
            FOREIGN KEY (voter) REFERENCES users(id),
            FOREIGN KEY (voting) REFERENCES voting(id)
        )
        ''')
        conn.commit()

    with sqlite3.connect(BLACKLIST_DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS blacklist (
            jti TEXT PRIMARY KEY
        )
        ''')
        conn.commit()


def verify_user(email, password):
    conn = sqlite3.connect(USERS_DATABASE)
    cursor = conn.cursor()
    
    cursor.execute(
        'SELECT password FROM users WHERE email = ?',
        (email,)
    )
    result = cursor.fetchone()
    conn.close()
    
    if not result:
        return False
    
    stored_hash = result[0]
    return bcrypt.checkpw(password.encode(), stored_hash.encode())


def add_user(name, email, password, public_key):
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    conn = sqlite3.connect(USERS_DATABASE)
    cursor = conn.cursor()

    try:
        cursor.execute('''
        INSERT INTO users (name, email, password, public_key)
        VALUES (?, ?, ?, ?)
        ''', (name, email, password_hash, public_key))
        conn.commit()
        return True
    
    except sqlite3.IntegrityError: # if user already exists
        return False
    
    finally:
        conn.close()


def get_user_by_email(email):
    conn = sqlite3.connect(USERS_DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        return None
    
    return dict(zip([column[0] for column in cursor.description], user))


def get_user_by_id(user_id):
    conn = sqlite3.connect(USERS_DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        return None
    
    return dict(zip([column[0] for column in cursor.description], user))


def get_votings():
    conn = sqlite3.connect(VOTINGS_DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM votings')
    votings = cursor.fetchall()
    conn.close()
    
    return [dict(zip([column[0] for column in cursor.description], row)) for row in votings]


def add_voting(voting):
    conn = sqlite3.connect(VOTINGS_DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('''
    INSERT INTO votings (name, multiple_votes, anonymous, is_private, options, whitelist, status, creator)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        voting['name'],
        voting['multiple_votes'],
        voting['anonymous'],
        voting['is_private'],
        ','.join(voting['options']),
        ','.join(voting.get('whitelist', [])),
        'Aberta',
        voting['creator']
    ))
    
    conn.commit()
    conn.close()


def add_vote(signed_vote, choice, voter, voting_id):
    conn = sqlite3.connect(VOTES_DATABASE)
    cursor = conn.cursor()

    cursor.execute('''
    INSERT INTO votes (signed_vote, choice, voter, voting)
    VALUES (?, ?, ?, ?)
    ''', (signed_vote, choice, voter, voting_id
    ))

    conn.commit()
    conn.close()


def list_votes_by_voting_id(voting_id):
    conn = sqlite3.connect(VOTES_DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM votes WHERE voting = ?', (voting_id,))
    votes = cursor.fetchall()
    conn.close()
    
    return [dict(zip([column[0] for column in cursor.description], row)) for row in votes]


def get_voting_by_id(voting_id):
    conn = sqlite3.connect(VOTINGS_DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM votings WHERE id = ?', (voting_id,))
    voting = cursor.fetchone()
    conn.close()
    
    if not voting:
        return None
    
    return dict(zip([column[0] for column in cursor.description], voting))


def close_voting_by_id(voting_id):
    conn = sqlite3.connect(VOTINGS_DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('UPDATE votings SET status = ? WHERE id = ?', ('Encerrada', voting_id))
    conn.commit()
    conn.close()


def add_jti_to_blacklist(jti):
    # add a JTI (JWT ID) to the blacklist
    try:
        with sqlite3.connect(BLACKLIST_DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO blacklist (jti) VALUES (?)', (jti,))
            conn.commit()
        return True
    except sqlite3.IntegrityError:
        # jti already in the blacklist
        return False


def is_blacklisted(jti):
    # check if a JTI is in the blacklist
    with sqlite3.connect(BLACKLIST_DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT 1 FROM blacklist WHERE jti = ? LIMIT 1', (jti,))
        return cursor.fetchone() is not None

init_db()