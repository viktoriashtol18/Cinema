import random
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity, get_jwt, verify_jwt_in_request
)
from functools import wraps
from datetime import datetime, timedelta
from passlib.hash import pbkdf2_sha256
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cinema.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'super-secret-key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.secret_key = 'super-secret-key-for-flask'

db = SQLAlchemy(app)
jwt = JWTManager(app)


# MODELS
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True)
    role = db.Column(db.String(20), default='user')

    def set_password(self, password):
        self.password_hash = pbkdf2_sha256.hash(password)

    def check_password(self, password):
        return pbkdf2_sha256.verify(password, self.password_hash)

class Session(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    movie_title = db.Column(db.String(100), nullable=False)
    hall = db.Column(db.String(50), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    total_seats = db.Column(db.Integer, nullable=False)
    available_seats = db.Column(db.Integer, nullable=False)

class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    session_id = db.Column(db.Integer, db.ForeignKey('session.id'), nullable=False)
    seat_number = db.Column(db.String(10))
    price = db.Column(db.Float)
    status = db.Column(db.String(20), default='issued')
    issue_date = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User')
    session = db.relationship('Session')



# HELPERS
def role_required(roles):
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            if claims['role'] not in roles:
                return jsonify(msg='Access forbidden'), 403
            return fn(*args, **kwargs)
        return decorator
    return wrapper


# FRONTEND ROUTES
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/sessions')
def sessions():
    sessions = Session.query.all()
    return render_template('sessions.html', sessions=sessions)


@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            access_token = create_access_token(
                identity=user.username,
                additional_claims={'role': user.role, 'user_id': user.id}
            )
            response = redirect(url_for('index'))
            response.set_cookie('access_token', access_token)
            flash('Logged in successfully!', 'success')
            return response
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html')


@app.route('/logout')
def logout():
    response = redirect(url_for('index'))
    response.set_cookie('access_token', '', expires=0)
    flash('Logged out successfully!', 'success')
    return response

# AUTH
@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if not user or not user.check_password(data['password']):
        return jsonify({'msg': 'Invalid credentials'}), 401
    access_token = create_access_token(identity=user.username, additional_claims={'role': user.role, 'user_id': user.id})
    return jsonify(access_token=access_token)

# USERS
@app.route('/api/cinema/users', methods=['GET'])
@jwt_required()
@role_required(['admin', 'user'])
def get_users():
    users = User.query.all()
    return jsonify([{ 'id': u.id, 'username': u.username, 'full_name': u.full_name, 'email': u.email, 'role': u.role } for u in users])

@app.route('/api/cinema/users', methods=['POST'])
@jwt_required()
@role_required(['admin'])
def create_user():
    data = request.get_json()
    user = User(username=data['username'], full_name=data['full_name'], email=data['email'], role=data.get('role', 'user'))
    user.set_password(data['password'])
    db.session.add(user)
    db.session.commit()
    return jsonify({'msg': 'User created', 'id': user.id}), 201

@app.route('/api/cinema/users/<int:user_id>', methods=['GET'])
@jwt_required()
@role_required(['admin', 'user'])
def get_user(user_id):
    claims = get_jwt()
    if claims['role'] != 'admin' and claims['user_id'] != user_id:
        return jsonify({'msg': 'Access denied'}), 403
    user = User.query.get_or_404(user_id)
    return jsonify({'id': user.id, 'username': user.username, 'full_name': user.full_name, 'email': user.email, 'role': user.role})

@app.route('/api/cinema/users/<int:user_id>', methods=['PUT'])
@jwt_required()
@role_required(['user', 'admin'])
def update_user(user_id):
    if get_jwt()['user_id'] != user_id:
        return jsonify({'msg': 'Can only update your own profile'}), 403
    user = User.query.get_or_404(user_id)
    data = request.get_json()
    user.full_name = data.get('full_name', user.full_name)
    user.email = data.get('email', user.email)
    db.session.commit()
    return jsonify({'msg': 'User updated'})

@app.route('/api/cinema/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
@role_required(['admin', 'user'])
def delete_user(user_id):
    if get_jwt()['role'] != 'admin' and get_jwt()['user_id'] != user_id:
        return jsonify({'msg': 'Access denied'}), 403
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({'msg': 'User deleted'})

# SESSIONS
@app.route('/api/cinema/sessions', methods=['GET'])
@jwt_required()
def get_sessions():
    sessions = Session.query.all()
    return jsonify([{ 'id': s.id, 'movie_title': s.movie_title, 'hall': s.hall, 'start_time': s.start_time.isoformat(), 'end_time': s.end_time.isoformat(), 'available_seats': s.available_seats } for s in sessions])

@app.route('/api/cinema/sessions', methods=['POST'])
@jwt_required()
@role_required(['admin'])
def create_session():
    data = request.get_json()
    session = Session(
        movie_title=data['movie_title'],
        hall=data['hall'],
        start_time=datetime.fromisoformat(data['start_time']),
        end_time=datetime.fromisoformat(data['end_time']),
        total_seats=data['total_seats'],
        available_seats=data['total_seats']
    )
    db.session.add(session)
    db.session.commit()
    return jsonify({'msg': 'Session created', 'id': session.id}), 201

@app.route('/api/cinema/sessions/<int:session_id>', methods=['PUT'])
@jwt_required()
@role_required(['admin'])
def update_session(session_id):
    session = Session.query.get_or_404(session_id)
    data = request.get_json()
    for field in ['movie_title', 'hall']:
        setattr(session, field, data.get(field, getattr(session, field)))
    db.session.commit()
    return jsonify({'msg': 'Session updated'})

@app.route('/api/cinema/sessions/<int:session_id>', methods=['DELETE'])
@jwt_required()
@role_required(['admin'])
def delete_session(session_id):
    session = Session.query.get_or_404(session_id)
    db.session.delete(session)
    db.session.commit()
    return jsonify({'msg': 'Session deleted'})

# TICKETS
@app.route('/api/cinema/sessions/<int:session_id>/tickets', methods=['POST'])
@jwt_required()
def buy_ticket(session_id):
    session = Session.query.get_or_404(session_id)
    if session.available_seats <= 0:
        return jsonify({'msg': 'No seats available'}), 400
    seat_number = request.json.get('seat_number')
    user_id = get_jwt()['user_id']
    ticket = Ticket(
        user_id=user_id,
        session_id=session.id,
        seat_number=seat_number,
        price=random.randint(200, 2000)
    )
    session.available_seats -= 1
    db.session.add(ticket)
    db.session.commit()
    return jsonify({'msg': 'Ticket purchased', 'ticket_id': ticket.id})

@app.route('/api/cinema/tickets/<int:ticket_id>', methods=['GET'])
@jwt_required()
@role_required(['admin', 'user'])
def get_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if get_jwt()['role'] != 'admin' and get_jwt()['user_id'] != ticket.user_id:
        return jsonify({'msg': 'Access denied'}), 403
    return jsonify({
        'id': ticket.id,
        'movie_title': ticket.session.movie_title,
        'seat_number': ticket.seat_number,
        'price': ticket.price,
        'issue_date': ticket.issue_date.isoformat(),
        'status': ticket.status
    })

if __name__ == '__main__':
    app.run(debug=True)
