import re
import secrets
import random, copy, subprocess
import sys
import os
import time
from flask import Blueprint, request, render_template, \
                  flash, g, session, redirect, url_for
from werkzeug.security import check_password_hash, generate_password_hash
import os
from app import app, ALLOWED_EXTENSIONS, BASE_DIR, static_folder
from app.auth.checker import checker
from werkzeug.utils import secure_filename
from flask_login import login_user, login_required, current_user, UserMixin, logout_user, login_manager
from flask_mail import Message
#from app.mod_auth.forms import LoginForm, SignupForm, RequestResetForm, ResetPasswordForm, UpdateAccountForm, SendmailsForm

mod_auth = Blueprint('auth', __name__, url_prefix='/auth')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/")
def home():
    return render_template("index.html")     
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            l = len(filename)
            filename1 = filename[:l-4]
            decompiled_file = BASE_DIR+'/app/static/decompiled_apks/'+filename1
            apk_file = BASE_DIR+'/app/static/uploaded_apks/'+filename
            command = 'jadx -d '+decompiled_file+' '+apk_file
            p = subprocess.Popen(command, shell=True, stdout = subprocess.PIPE)
            stdout, stderr = p.communicate()
            isadb_backup = False
            if checker.backup_enabled(decompiled_file+'/resources/AndroidManifest.xml','application','allowBackup'):
                isadb_backup = True
            
            print(checker.backup_enabled(decompiled_file+'/resources/AndroidManifest.xml','application','allowBackup'))
            secrets_data = checker.scan_for_secrets(decompiled_file, verbose=True)
            return render_template('secrets.html', secrets_data=secrets_data,isadb_backup=isadb_backup, apkname= filename1)

            
    return render_template('upload.html')



@mod_auth.route("/temp")
def logout():
    """User log-out logic."""
    #logout_user()
    flash(f'You have been Logged Out!!', 'success')
    return redirect(url_for('auth.signin'))