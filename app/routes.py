import logging, requests, json
from app import app, db
from flask import session, redirect, render_template, url_for, make_response, request
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_restful import Resource, Api
from msal import ConfidentialClientApplication
import os.path
from csv import DictReader

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
        credentials.get('CLIENT_ID', {}),
        authority=credentials.get('AUTHORITY', {}),
        client_credential=credentials.get('CLIENT_SECRET', {})
    )
    result = None
    scope = credentials.get('SCOPE', {})
    result = appMS.acquire_token_silent(scopes=list(scope), account=None)
    if not result:
        logging.info("No suitable token exists in cache. Let's get a new one from AAD.")
        result = appMS.acquire_token_for_client(scopes=scope)

    token = result.get('access_token', {})
    return token

# get user id for contact update
def getId(email):
    with open("app/json_files/apis.json") as f:
        apis = json.load(f)
    with open("app/json_files/headers.json") as f:
        headers = json.load(f)
    url = apis.get('create_contact', {})
    token = generatetoken()
    token = 'Bearer {}'.format(token)
    headers["headers"]["createContact"]["Authorization"] = token
    headers = headers["headers"]["createContact"]

    r = requests.get(url, headers=headers)
    data = r.json()
    data = data.get('value', {})
    for i in data:
        if i["emailAddresses"][0]["address"] == email:
            user_id = i["id"]
            return user_id

#To create & read Report-CSV File
def createCsv(url,headers,file):
    r = requests.get(url, headers=headers)

    my_path = os.path.abspath(os.path.dirname(__file__))
    path = os.path.join(my_path, file)
    f = open(path, "w")
    f.write(r.text)

def readCsv(file):
    my_path = os.path.abspath(os.path.dirname(__file__))
    path = os.path.join(my_path, file)
    list_report = []
    with open(path) as read_obj:
        csv_reader = DictReader(read_obj)
        print(csv_reader)
        for i in csv_reader:
            list_report.append(dict(i))
    return list_report

class index(Resource):
    def __init__(self):
        pass

    def get(self):
        #return redirect(url_for('login'))
        return make_response(render_template('dashboard.html'))

class login(Resource):
    def get(self):
        return make_response(render_template('login.html'))

    def post(self):
        user = User.query.filter_by(username=request.form["username"]).first()
        if user:
            if check_password_hash(user.password, request.form["password"]):
                login_user(user)
                return redirect(url_for('dashboard'))

        with open("app/json_files/error_messages.json") as f:
            errors = json.load(f)
        errors["error_message"] = 'Invalid Username or Password!'
        return make_response(render_template('login.html', errors=errors["error_message"]))

class signup(Resource):
    def get(self):
        return make_response(render_template('signup.html'))

    def post(self):
        firstname = request.form["firstname"]
        lastname = request.form["lastname"]
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        user = User.query.filter_by(username=request.form["username"]).first()
        if user:
            with open("app/json_files/error_messages.json") as f:
                errors = json.load(f)
            errors["error_message"] = 'User already exist. kindly login!'
            return make_response(render_template('login.html', errors=errors.get('error_message', {})))

        if password != request.form["confirmpassword"]:
            with open("app/json_files/error_messages.json") as f:
                errors = json.load(f)
            errors["error_message"] = 'Passwords do not match! Try again.'
            return make_response(render_template('signup.html', errors=errors.get('error_message', {})))

        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(firstname=firstname, lastname=lastname, username=username,
                        email=email, password=hashed_password)

        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))


class logout(Resource):
    @login_required
    def get(self):
        session.clear()
        logout_user()
        return redirect(url_for('index'))

class dashboard(Resource):
    def get(self):
        return make_response(render_template('dashboard.html'))

class createContact(Resource):
    def get(self):
        return make_response(render_template('contacts/createcontact.html'))

    def post(self):
        with open("app/json_files/apis.json") as f:
            apis = json.load(f)
        with open("app/json_files/headers.json") as f:
            headers = json.load(f)
        with open('app/json_files/body.json') as f:
            body = json.load(f)

        url = apis.get('create_contact', {})
        token = generatetoken()
        token = 'Bearer {}'.format(token)
        headers["headers"]["createContact"]["Authorization"] = token
        headers = headers["headers"]["createContact"]

        body["contactBody"]["givenName"] = request.form["firstname"]
        body["contactBody"]["surname"] = request.form["lastname"]
        body["contactBody"]["emailAddresses"][0]["address"] = request.form["email"]
        body["contactBody"]["companyName"] = request.form["companyname"]
        body["contactBody"]["businessHomePage"] = request.form["businesshomepage"]
        body["contactBody"]["department"] = request.form["department"]
        body["contactBody"]["officeLocation"] = request.form["officeLocation"]
        body["contactBody"]["businessPhones"][0] = request.form["mobilenumber"]
        body = body.get('contactBody', {})

        requests.post(url, headers=headers, data=json.dumps(body))
        return redirect(url_for('listcontact'))

class listContact(Resource):
    def get(self):
        with open("app/json_files/apis.json") as f:
            apis = json.load(f)
        with open("app/json_files/headers.json") as f:
            headers = json.load(f)

        url = apis.get('create_contact', {})
        token = generatetoken()
        token = 'Bearer {}'.format(token)
        headers["headers"]["createContact"]["Authorization"] = token
        headers = headers["headers"]["createContact"]

        data = requests.get(url, headers=headers)
        data = data.json()

        # listdata = data["value"]
        # sub_url = data["@odata.nextLink"]
        # while sub_url != "":
        #     sub_response = request.get(sub_url, headers=headers)
        #     listdata.extend(sub_response["value"])
        #     sub_url = sub_response["@odata.nextLink"]
        # data = listdata.json()
        return make_response(render_template("contacts/listcontact.html", data=data))

class updateContact(Resource):
    def get(self):
        return make_response(render_template('contacts/updatecontact.html'))

    def post(self,email):
        with open("app/json_files/apis.json") as f:
            apis = json.load(f)
        with open("app/json_files/headers.json") as f:
            headers = json.load(f)
        with open('app/json_files/body.json') as f:
            body = json.load(f)

        firstname = request.form["firstname"]
        lastname = request.form["lastname"]
        oldemail = email
        newemail = request.form["newemail"]
        mobilenumber = request.form["mobilenumber"]

        id = getId(oldemail)
        if id:
            url = apis.get('create_contact', {}) + "/"+id
            token = generatetoken()
            token = 'Bearer {}'.format(token)
            headers["headers"]["createContact"]["Authorization"] = token
            headers = headers["headers"]["createContact"]
            body["contactBody"]["givenName"] = firstname
            body["contactBody"]["surname"] = lastname
            body["contactBody"]["emailAddresses"][0]["address"] = newemail
            body["contactBody"]["businessPhones"][0] = mobilenumber
            body = body.get('contactBody', {})

            r = requests.patch(url, headers=headers, data=json.dumps(body))
            return redirect(url_for('listcontact'))
        return make_response(render_template("contacts/updatecontact.html", errors="Email is not available"))


class deleteContact(Resource):
    def get(self):
        return make_response(render_template('contacts/deletecontact.html'))

    def post(self,email):
        with open("app/json_files/apis.json") as f:
            apis = json.load(f)
        with open("app/json_files/headers.json") as f:
            headers = json.load(f)
        print(email)
        #email = request.form["get_email"]
        id = getId(email)
        if id:
            url = apis.get('create_contact', {}) + "/"+id
            token = generatetoken()
            token = 'Bearer {}'.format(token)
            headers["headers"]["createContact"]["Authorization"] = token
            headers = headers["headers"]["createContact"]
            r = requests.delete(url, headers=headers)
            return redirect(url_for('listcontact'))
        return make_response(render_template("contacts/deletecontact.html", errors="Email is not available!"))

class outlook(Resource):
    def get(self):
        with open("app/json_files/apis.json") as f:
            apis = json.load(f)
        with open("app/json_files/headers.json") as f:
            headers = json.load(f)

        userActivity_file = " userActivity.csv"
        url = apis.get('getEmailActivityUserDetail', {})
        token = generatetoken()
        token = 'Bearer {}'.format(token)
        headers["headers"]["getEmailActivityUserDetail"]["Authorization"] = token
        headers = headers["headers"]["getEmailActivityUserDetail"]

        createCsv(url,headers,userActivity_file)
        data = readCsv(userActivity_file)

        userActivityCount_file = " userActivityCount.csv"
        url = apis.get('getEmailActivityCounts', {})
        createCsv(url, headers, userActivityCount_file)
        datacount = readCsv(userActivityCount_file)

        return make_response(render_template('report/outlook.html', data=data,datacount=datacount))

api.add_resource(index, '/')
api.add_resource(login, '/login')
api.add_resource(signup, '/signup')
api.add_resource(logout, '/logout')
api.add_resource(dashboard, '/dashboard')
api.add_resource(createContact, '/createContact')
api.add_resource(listContact, '/listContact')
api.add_resource(updateContact,'/updateContact')
api.add_resource(deleteContact,"/deleteContact/","/deleteContact/<string:email>")
api.add_resource(outlook,"/outlook")