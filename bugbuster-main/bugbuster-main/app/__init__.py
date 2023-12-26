from flask import Flask, redirect, url_for, request, render_template, flash, json, jsonify
from flask_mongoengine import MongoEngine
import urllib, subprocess, time, os, uuid
from werkzeug.utils import secure_filename
from flask_login import LoginManager
from werkzeug.exceptions import HTTPException
from config import BASE_DIR, SECRET_KEY

UPLOAD_FOLDER = BASE_DIR+'/app/static/uploaded_apks/'
static_folder = BASE_DIR+'/app/static/output/'
ALLOWED_EXTENSIONS = {'apk'}

app = Flask(__name__)

app.debug = True
app.config.from_object('config')
app.config[SECRET_KEY] = 'qwerty'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
#db = MongoEngine()
#db.init_app(app)



@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

'''@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500'''

'''@app.errorhandler(Exception)
def handle_exception(e):
    if isinstance(e, HTTPException):
        return e

    return render_template("500.html"), 500'''


from app.auth.controller import mod_auth as auth_module
app.register_blueprint(auth_module)
#app.register_error_handler(500, internal_server_error)
app.register_error_handler(404, not_found)

if __name__ == "__main__":
    app.run(debug=True)