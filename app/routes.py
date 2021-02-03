import logging, requests, json
from app import app, db
from flask import session, redirect, render_template, url_for, flash, make_response
from .models import User
from .forms import LoginForm, SignupForm, PersonalContactForm
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_restful import Resource, Api
from msal import ConfidentialClientApplication

api = Api(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def generatetoken():
    with open('app/json_files/credential.json') as f:
        credentials = json.load(f)

    appMS = ConfidentialClientApplication(
        credentials["CLIENT_ID"],
        authority=credentials["AUTHORITY"],
        client_credential=credentials["CLIENT_SECRET"]
    )
    result = None
    result = appMS.acquire_token_silent(scopes=list(credentials["SCOPE"]), account=None)
    if not result:
        logging.info("No suitable token exists in cache. Let's get a new one from AAD.")
        result = appMS.acquire_token_for_client(scopes=credentials["SCOPE"])

    token = result['access_token']
    return token

# @app.route('/index')
class index(Resource):
    def __init__(self):
        pass

    def get(self):
        return make_response(render_template('index.html'))

# @app.route('/login', methods=['GET','POST'])
class login(Resource):
    def get(self):
        form = LoginForm()
        return make_response(render_template('login.html', form=form))

    def post(self):
        form = LoginForm()
        contact_form = PersonalContactForm()
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            if user:
                if check_password_hash(user.password, form.password.data):
                    login_user(user)
                    return make_response(render_template('dashboard.html', form=contact_form))
        with open("app/json_files/error_messages.json") as f:
            errors = json.load(f)
        errors["error_message"] = 'Invalid Username or Password!'
        return make_response(render_template('login.html', form=form, errors=errors["error_message"]))



# @app.route('/signup', methods=['GET','POST'])
class signup(Resource):
    def get(self):
        form = SignupForm()
        return make_response(render_template('signup.html', form=form))

    def post(self):
        form = SignupForm()
        if form.validate_on_submit():
            if form.password.data != form.confirmpassword.data:
                with open("app/json_files/error_messages.json") as f:
                    errors = json.load(f)
                errors["error_message"] = 'Passwords do not match! Try again.'
                return make_response(render_template('signup.html', form=form, errors=errors["error_message"]))
            hashed_password = generate_password_hash(form.password.data, method='sha256')
            new_user = User(firstname=form.firstname.data, lastname=form.lastname.data, username=form.username.data,email=form.email.data, password=hashed_password, confirmpassword=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
        return make_response(render_template('signup.html', form=form))

# @app.route('/logout')
# @login_required
class logout(Resource):
    def get(self):
        session.clear()
        logout_user()
        return redirect(url_for('index'))

# create contact
class createContact(Resource):
    def get(self):
        form = PersonalContactForm()
        return make_response(render_template('dashboard.html', form=form))

    def post(self):
        form = PersonalContactForm()
        if form.validate_on_submit():
            with open("app/json_files/apis.json") as f:
                apis = json.load(f)
            with open("app/json_files/headers.json") as f:
                headers = json.load(f)
            with open('app/json_files/body.json') as f:
                body = json.load(f)
            url = apis['create_contact']

            token = generatetoken()
            token = 'Bearer {}'.format(token)
            headers["headers"]["createContact"]["Authorization"] = token
            headers = headers["headers"]["createContact"]

            body["contactBody"]["givenName"] = form.firstname.data
            body["contactBody"]["surname"] = form.lastname.data
            body["contactBody"]["emailAddresses"][0]["address"] = form.email.data
            body["contactBody"]["businessPhones"][0] = form.mobilenumber.data
            body = body["contactBody"]

            r = requests.post(url, headers=headers, data=json.dumps(body))
            #print(r.json())
            return make_response(render_template('AddContactSuccess.html'))

# List contact
class listContact(Resource):
    def get(self):
        with open("app/json_files/apis.json") as f:
            apis = json.load(f)
        with open("app/json_files/headers.json") as f:
            headers = json.load(f)

        url = apis['create_contact']
        token = generatetoken()
        token = 'Bearer {}'.format(token)
        headers["headers"]["createContact"]["Authorization"] = token
        headers = headers["headers"]["createContact"]

        data = requests.get(url, headers=headers)
        data = data.json()
        return make_response(render_template("showContact.html",data=data))

# Microsoft teams user activity(get)
class getUserActivity(Resource):
    def get(self):
        url = "https://graph.microsoft.com/v1.0/reports/getTeamsUserActivityUserDetail(period='D7')"
        headers = {
            'Authorization': 'Bearer {}'.format(generatetoken()),
            'Content-Type': 'application/json'
        }
        data = requests.get(url, headers=headers)
        return data.text

# Microsoft teams user activity counts(get)
class getTeamsUserActivityCounts(Resource):
    def get(self):
        url = "https://graph.microsoft.com/v1.0/reports/getTeamsUserActivityCounts(period='D7')"
        headers = {
            'Authorization': 'Bearer {}'.format(generatetoken()),
            'Content-Type': 'application/json'
        }
        data = requests.get(url, headers=headers)
        return data.text

# Microsoft teams user activity use counts(get user detail by activity type)
class getTeamsUserActivityUserCounts(Resource):
    def get(self):
        url = "https://graph.microsoft.com/v1.0/reports/getTeamsUserActivityUserCounts(period='D7')"
        headers = {
            'Authorization': 'Bearer {}'.format(generatetoken()),
            'Content-Type': 'application/json'
        }
        data = requests.get(url, headers=headers)
        return data.text

# Outlook email user activity
class getEmailActivityUserDetail(Resource):
    def get(self):
        url = "https://graph.microsoft.com/v1.0/reports/getEmailActivityUserDetail(period='D7')"
        headers = {
            'Authorization': 'Bearer {}'.format(generatetoken()),
            'Content-Type': 'application/json'
        }
        data = requests.get(url, headers=headers)
        return data.text

# Outlook email activity count
class getEmailActivityCounts(Resource):
    def get(self):
        url = "https://graph.microsoft.com/v1.0/reports/getEmailActivityCounts(period='D7')"
        headers = {
            'Authorization': 'Bearer {}'.format(generatetoken()),
            'Content-Type': 'application/json'
        }
        data = requests.get(url, headers=headers)
        return data.text

# Outlook email user activity count
class getEmailActivityUserCounts(Resource):
    def get(self):
        url = "https://graph.microsoft.com/v1.0/reports/getEmailActivityUserCounts(period='D7')"
        headers = {
            'Authorization': 'Bearer {}'.format(generatetoken()),
            'Content-Type': 'application/json'
        }
        data = requests.get(url, headers=headers)
        return data.text

# Onedrive user activity
class getOneDriveActivityUserDetail(Resource):
    def get(self):
        url = "https://graph.microsoft.com/v1.0/reports/getOneDriveActivityUserDetail(period='D7')"
        headers = {
            'Authorization': 'Bearer {}'.format(generatetoken()),
            'Content-Type': 'application/json'
        }
        data = requests.get(url, headers=headers)
        return data.text

# Onedrive user activity count
class getOneDriveActivityUserCounts(Resource):
    def get(self):
        url = "https://graph.microsoft.com/v1.0/reports/getOneDriveActivityUserCounts(period='D7')"
        headers = {
            'Authorization': 'Bearer {}'.format(generatetoken()),
            'Content-Type': 'application/json'
        }
        data = requests.get(url, headers=headers)
        return data.text

# Onedrive activity file counts(Get the number of unique, licensed users that performed file interactions against any OneDrive account)
class getOneDriveActivityFileCounts(Resource):
    def get(self):
        url = "https://graph.microsoft.com/v1.0/reports/getOneDriveActivityFileCounts(period='D7')"
        headers = {
            'Authorization': 'Bearer {}'.format(generatetoken()),
            'Content-Type': 'application/json'
        }
        data = requests.get(url, headers=headers)
        return data.text

api.add_resource(index, '/')
api.add_resource(login, '/login')
api.add_resource(signup, '/signup')
api.add_resource(logout, '/logout')
api.add_resource(createContact, '/createContact')
api.add_resource(listContact, '/listContact')
api.add_resource(getUserActivity, '/getUserActivity')
api.add_resource(getTeamsUserActivityCounts, '/getTeamsUserActivityCounts')
api.add_resource(getTeamsUserActivityUserCounts, '/getTeamsUserActivityUserCounts')
api.add_resource(getEmailActivityUserDetail, '/getEmailActivityUserDetail')
api.add_resource(getEmailActivityCounts, '/getEmailActivityCounts')
api.add_resource(getEmailActivityUserCounts, '/getEmailActivityUserCounts')
api.add_resource(getOneDriveActivityUserDetail,'/getOneDriveActivityUserDetail')
api.add_resource(getOneDriveActivityUserCounts,'/getOneDriveActivityUserCounts')
api.add_resource(getOneDriveActivityFileCounts,'/getOneDriveActivityFileCounts')
