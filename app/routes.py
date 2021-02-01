from app import app
from app import db
from flask import request, session, redirect, render_template, url_for, flash,make_response
from .models import User
from .forms import LoginForm, SignupForm
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_restful import Resource, Api

api = Api(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#@app.route('/index')
class index(Resource):
    def __init__(self):
        pass
    def get(self):
        return make_response(render_template('index.html'))

#@app.route('/login', methods=['GET','POST'])
class login(Resource):
    def get(self):
        form = LoginForm()
        return make_response(render_template('login.html', form=form))

    def post(self):
        form = LoginForm()
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            if user:
                if check_password_hash(user.password,form.password.data):
                    login_user(user)
                    return make_response(render_template('dashboard.html', form=form))
            flash('Invalid Username or Password', 'danger')

#@app.route('/signup', methods=['GET','POST'])
class signup(Resource):
    def get(self):
        form = SignupForm()
        return make_response(render_template('signup.html', form=form))

    def post(self):
        form = SignupForm()
        if form.validate_on_submit():
            if form.password.data != form.confirmpassword.data :
                flash('Passwords do not match! Try again.', 'danger')
                return make_response(render_template('signup.html', form=form))
            hashed_password = generate_password_hash(form.password.data,method='sha256')
            new_user = User(firstname=form.firstname.data, lastname=form.lastname.data, username=form.username.data,email=form.email.data, password=hashed_password, confirmpassword=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))

#@app.route('/logout')
#@login_required
class logout(Resource):
    def get(self):
        session.clear()
        logout_user()
        return redirect(url_for('index'))

api.add_resource(index, '/')
api.add_resource(login, '/login')
api.add_resource(signup, '/signup')
api.add_resource(logout, '/logout')
