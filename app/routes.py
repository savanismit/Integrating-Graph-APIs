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
import datetime
from datetime import datetime

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


# To create & read Report-CSV File
def createCsv(url, headers, file):
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
        return redirect(url_for('login'))

class dashboard(Resource):
    @login_required
    def get(self):
        username = session.get("USERNAME")
        return make_response(render_template('dashboard.html',username=username))

class login(Resource):
    def get(self):
        return make_response(render_template('login.html'))

    def post(self):
        user = User.query.filter_by(username=request.form["username"]).first()
        if user:
            if check_password_hash(user.password, request.form["password"]):
                login_user(user)
                session["USERNAME"] = user.username
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
        return redirect(url_for('login'))


class createContact(Resource):
    @login_required
    def get(self):
        username = session.get("USERNAME")
        return make_response(render_template('contacts/createcontact.html',username=username))

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
    @login_required
    def get(self):
        username = session.get("USERNAME")
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
        return make_response(render_template("contacts/listcontact.html", data=data,username=username))


class updateContact(Resource):
    @login_required
    def get(self, email):
        username = session.get("USERNAME")
        return make_response(render_template('contacts/updatecontact.html', email=email,username=username))

    def post(self):
        username = session.get("USERNAME")
        with open("app/json_files/apis.json") as f:
            apis = json.load(f)
        with open("app/json_files/headers.json") as f:
            headers = json.load(f)
        with open('app/json_files/body.json') as f:
            body = json.load(f)
        oldemail = request.form["oldemail"]

        id = getId(oldemail)
        if id:
            url = apis.get('create_contact', {}) + "/" + id
            token = generatetoken()
            token = 'Bearer {}'.format(token)
            headers["headers"]["createContact"]["Authorization"] = token
            headers = headers["headers"]["createContact"]
            body["contactBody"]["givenName"] = request.form["firstname"]
            body["contactBody"]["surname"] = request.form["lastname"]
            body["contactBody"]["emailAddresses"][0]["address"] = request.form["newemail"]
            body["contactBody"]["companyName"] = request.form["companyname"]
            body["contactBody"]["businessHomePage"] = request.form["businesshomepage"]
            body["contactBody"]["department"] = request.form["department"]
            body["contactBody"]["officeLocation"] = request.form["officeLocation"]
            body["contactBody"]["businessPhones"][0] = request.form["mobilenumber"]
            body = body.get('contactBody', {})

            r = requests.patch(url, headers=headers, data=json.dumps(body))
            return redirect(url_for('listcontact'))
        return make_response(render_template("contacts/updatecontact.html", errors="Email is not available",username=username))


class deleteContact(Resource):
    @login_required
    def get(self):
        username = session.get("USERNAME")
        return make_response(render_template('contacts/deletecontact.html',username=username))

    def post(self, email):
        username = session.get("USERNAME")
        with open("app/json_files/apis.json") as f:
            apis = json.load(f)
        with open("app/json_files/headers.json") as f:
            headers = json.load(f)
        id = getId(email)
        if id:
            url = apis.get('create_contact', {}) + "/" + id
            token = generatetoken()
            token = 'Bearer {}'.format(token)
            headers["headers"]["createContact"]["Authorization"] = token
            headers = headers["headers"]["createContact"]
            r = requests.delete(url, headers=headers)
            return redirect(url_for('listcontact'))
        return make_response(render_template("contacts/deletecontact.html", errors="Email is not available!",username=username))


class outlook(Resource):
    @login_required
    def get(self):
        username = session.get("USERNAME")
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

        createCsv(url, headers, userActivity_file)
        data = readCsv(userActivity_file)

        userActivityCount_file = " userUsageDetail.csv"
        url = apis.get('getEmailAppUsageUserDetail', {})
        createCsv(url, headers, userActivityCount_file)
        datacount = readCsv(userActivityCount_file)

        return make_response(render_template('report/outlook.html', data=data, datacount=datacount,username=username))


class onedrive(Resource):
    def get(self):
        username = session.get("USERNAME")
        with open("app/json_files/apis.json") as f:
            apis = json.load(f)
        with open("app/json_files/headers.json") as f:
            headers = json.load(f)
        userActivity_file = " userActivity.csv"
        url = apis.get('getOneDriveActivityUserDetail', {})
        token = generatetoken()
        token = 'Bearer {}'.format(token)
        headers["headers"]["getOneDriveActivityUserDetail"]["Authorization"] = token
        headers = headers["headers"]["getOneDriveActivityUserDetail"]
        createCsv(url,headers,userActivity_file)
        data = readCsv(userActivity_file)
        userActivityCount_file = " userActivityCount.csv"
        url = apis.get('getOneDriveActivityUserCounts', {})
        createCsv(url, headers, userActivityCount_file)
        datacount = readCsv(userActivityCount_file)
        return make_response(render_template('report/onedrive.html', data=data,datacount=datacount, username=username))


class reportgraph(Resource):
    def get(self):
        username = session.get("USERNAME")
        with open("app/json_files/apis.json") as f:
            apis = json.load(f)
        with open("app/json_files/headers.json") as f:
            headers = json.load(f)

        url = "https://graph.microsoft.com/v1.0/users/smit.s@turabittrialtest.onmicrosoft.com/drive/root/children"
        token = generatetoken()
        token = 'Bearer {}'.format(token)
        headers["headers"]["getEmailActivityUserDetail"]["Authorization"] = token
        headers = headers["headers"]["getEmailActivityUserDetail"]

        data = requests.get(url, headers=headers)
        data = data.json()
        size = [["Name", "Size"]]
        for i in data["value"]:
            size.append([i["name"], (round(i["size"] / (1024 ** 2), 2))])
        print(size)
        return make_response(render_template('report/reportgraph.html', data=size,username=username))


class AutoForward(Resource):
    @login_required
    def get(self):
        username = session.get("USERNAME")
        return make_response(render_template('email/autoforward.html',username=username))

    def post(self):
        username = session.get("USERNAME")
        with open("app/json_files/apis.json") as f:
            apis = json.load(f)
        with open("app/json_files/headers.json") as f:
            headers = json.load(f)
        with open('app/json_files/body.json') as f:
            body = json.load(f)
        url = apis.get('AutoForwardEmail', {})
        token = generatetoken()
        token = 'Bearer {}'.format(token)
        headers["headers"]["AutoForwardEmail"]["Authorization"] = token
        headers = headers["headers"]["AutoForwardEmail"]
        body["AutoForwardBody"]["actions"]["forwardTo"][0]["emailAddress"]["address"] = request.form["email_to"]

        if request.form["option"] == "Disabled":
            data = "Auto Forward is successfully Disabled!"
            body["AutoForwardBody"]["isEnabled"] = "false"
        else:
            body["AutoForwardBody"]["conditions"]["sentToMe"] = "true"
            data = "Auto Forward is successfully Enabled!"
            body["AutoForwardBody"]["isEnabled"] = "true"
        body = body.get('AutoForwardBody', {})

        r = requests.post(url, headers=headers, data=json.dumps(body))
        print(r.json())
        return make_response(render_template('email/autoforward.html', data=data,username=username))


class AutoReplyEmail(Resource):
    @login_required
    def get(self):
        username = session.get("USERNAME")
        return make_response(render_template('email/autoreply.html',username=username))

    def post(self):
        username = session.get("USERNAME")
        with open("app/json_files/apis.json") as f:
            apis = json.load(f)
        with open("app/json_files/headers.json") as f:
            headers = json.load(f)
        with open('app/json_files/body.json') as f:
            body = json.load(f)
        url = apis.get('AutoReplyEmail', {})
        token = generatetoken()
        token = 'Bearer {}'.format(token)
        headers["headers"]["AutoReplyEmail"]["Authorization"] = token
        headers = headers["headers"]["AutoReplyEmail"]
        urlTime = apis.get('timeZone', {})
        time = requests.get(urlTime, headers=headers).json()

        if request.form["option"] == "Disabled":
            body["AutoReplyEmailBody"]["automaticRepliesSetting"]["status"] = "disabled"
        elif request.form["option"] == "Enabled":
            body["AutoReplyEmailBody"]["automaticRepliesSetting"]["internalReplyMessage"] = request.form["reply1"]
            body["AutoReplyEmailBody"]["automaticRepliesSetting"]["externalReplyMessage"] = request.form["reply2"]
            body["AutoReplyEmailBody"]["automaticRepliesSetting"]["status"] = "alwaysEnabled"
        else:
            start_date_time = request.form["starttime"]
            end_date_time = request.form["endtime"]

            start_date_time_obj = datetime.fromisoformat(start_date_time)
            end_date_time_obj = datetime.fromisoformat(end_date_time)

            curr_time = datetime.fromisoformat(str(datetime.now())[:-7])
            diff_time1 = ((start_date_time_obj - curr_time).total_seconds()) / 60

            diff_time2 = ((end_date_time_obj - start_date_time_obj).total_seconds()) / 60

            if diff_time1 < 10:
                errors = "Your start time should be 10 minutes more than current time!"
                return make_response(render_template('email/autoreply.html', errors=errors,username=username))
            elif diff_time2 < 60:
                errors = "Your end time should be 1 hour more than your start time!"
                return make_response(render_template('email/autoreply.html', errors=errors,username=username))
            else:
                body["AutoReplyEmailBody"]["automaticRepliesSetting"]["internalReplyMessage"] = request.form["reply1"]
                body["AutoReplyEmailBody"]["automaticRepliesSetting"]["externalReplyMessage"] = request.form["reply2"]
                body["AutoReplyEmailBody"]["automaticRepliesSetting"]["status"] = "scheduled"
                body["AutoReplyEmailBody"]["automaticRepliesSetting"]["scheduledStartDateTime"]["dateTime"] = start_date_time
                body["AutoReplyEmailBody"]["automaticRepliesSetting"]["scheduledEndDateTime"]["dateTime"] = end_date_time
                body["AutoReplyEmailBody"]["automaticRepliesSetting"]["scheduledStartDateTime"]["timeZone"] = time["value"]
                body["AutoReplyEmailBody"]["automaticRepliesSetting"]["scheduledEndDateTime"]["timeZone"] = time["value"]
        body = body.get('AutoReplyEmailBody', {})

        r = requests.patch(url, headers=headers, data=json.dumps(body))
        print(r.json())
        if request.form["option"] == "Disabled":
            data = "Auto Reply is disabled successfully!"
        else:
            data = "Auto Reply is successfully set!"
        return make_response(render_template('email/autoreply.html', data=data,username=username))


api.add_resource(index, '/')
api.add_resource(login, '/login')
api.add_resource(signup, '/signup')
api.add_resource(logout, '/logout')
api.add_resource(dashboard, '/dashboard')
api.add_resource(createContact, '/createContact')
api.add_resource(listContact, '/listContact')
api.add_resource(updateContact, "/updateContact", "/updateContact/<string:email>")
api.add_resource(deleteContact, "/deleteContact", "/deleteContact/<string:email>")
api.add_resource(outlook, "/outlook")
api.add_resource(onedrive, "/onedrive")
api.add_resource(reportgraph, "/reportgraph")
api.add_resource(AutoForward, "/autoforward")
api.add_resource(AutoReplyEmail, "/autoreply")
