import os,requests,json

from flask import Flask, request, redirect, url_for, flash
from flask import render_template
from flask import jsonify

from flask_socketio import SocketIO,emit
from flask_sqlalchemy import SQLAlchemy
from flask_login import current_user, login_user, login_required, LoginManager

from werkzeug.security import generate_password_hash,check_password_hash

from flask_heroku import Heroku

from forms import Login,Register


app = Flask(__name__)
app.config.from_object('config')

socketio = SocketIO(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://qeschskqymhhuy:e92ff18d8fad3e20c31febcd647d8c4aad0cc48de7d1c5a2a957ecee4919b772@ec2-174-129-223-193.compute-1.amazonaws.com:5432/d814036na56rtq'
heroku = Heroku(app)
db = SQLAlchemy(app)

login_manager= LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'
login_manager.init_app(app)

# Create our database model
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), index=True, unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True)
    password_hash = db.Column(db.String(128),nullable=False)
    mobile = db.Column(db.Integer, unique=True)

    def __init__(self, email, username, password, mobile):
        self.email = email
        self.username = username
        self.password = password
        self.mobile = mobile
    def __repr__(self):
        return '<title {}'.format(self.name)

    def is_active(self):
        """True, as all users are active."""
        return True

    def get_id(self):
        """Return the email address to satisfy Flask-Login's requirements."""
        return self.username

    def is_authenticated(self):
        """Return True if the user is authenticated."""
        return self.authenticated

    def is_anonymous(self):
        """False, as anonymous users aren't supported."""
        return False

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    @login_manager.user_loader
    def load_user(username):
    	return User.query.filter_by(username=username).first()

@app.route("/")
def index():
	return render_template("index.html",title="Home")

@app.route("/signin",methods=['GET','POST'])
def signin():
    form = Login()
    if current_user.is_authenticated:
        return redirect(url_for('chat'))
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.username.data).first()
        print form.username.data
        if user is not None and user.verify_password(form.password.data):
            user.authenticated = True
            print "hello"
            db.session.add(user)
            db.session.commit()
            login_user(user)
            return redirect(request.args.get('next') or url_for('chat'))
        flash('Invalid username or password.')
    return render_template('signin.html',title='Login',form=form)

@app.route("/register",methods=['GET','POST'])
def register():
    form = Register()
    if form.validate_on_submit():
        email = form.username.data
        username = form.username.data
        password = form.password.data
        mobile = form.mobile.data
        if not db.session.query(User).filter(User.email == email).count():
            reg = User(email,username,password,mobile)
            db.session.add(reg)
            db.session.commit()
    return render_template('register.html',title='Register',form=form)

@app.route("/chat",methods=['GET'])
def chat():
    return render_template("chat.html")

@socketio.on('my event', namespace='/test')
def test_message(message):
    
    print message['data']

    message_text = message['data']
    server_url = "https://ccbserver.herokuapp.com/api/msg/"

    final_url = server_url+message_text
    resp = requests.get(final_url)
    msg = json.loads(resp.text)
    bot_response = msg['response'][0]['output']
	    
    # checking if a matched response is found.
    if not bot_response:
        bot_response = "error"

    print bot_response

    emit('my response', {'data': bot_response})

@socketio.on('connect', namespace='/test')
def test_connect():
    emit('my response', {'data': 'Connected'})

@socketio.on('disconnect', namespace='/test')
def test_disconnect():
    print('Client disconnected')


if __name__ == "__main__":
	port = int(os.environ.get('PORT', 5555))
	socketio.run(app, debug=True)