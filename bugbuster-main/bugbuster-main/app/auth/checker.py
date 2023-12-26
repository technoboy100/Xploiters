import re, untangle
import secrets
import random, copy, subprocess
from flask import Blueprint, request, render_template, \
                  flash, g, session, redirect, url_for
from werkzeug.security import check_password_hash, generate_password_hash
import os
from app import app, ALLOWED_EXTENSIONS, BASE_DIR, static_folder
from werkzeug.utils import secure_filename
from flask_login import login_user, login_required, current_user, UserMixin, logout_user
from flask_mail import Message
from xml.dom import minidom


regex = {
    'google_api_key': r'AIza[0-9A-Za-z-_]{35}',
    'firebase'  : r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
    'google_captcha' : r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$',
    'google_oauth'   : r'ya29\.[0-9A-Za-z\-_]+',
    'amazon_aws_access_key_id' : r'A[SK]IA[0-9A-Z]{16}',
    'amazon_mws_auth_toke' : r'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    'amazon_aws_url' : r's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com',
    'amazon_aws_url2' : r"(" \
           r"[a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com" \
           r"|s3://[a-zA-Z0-9-\.\_]+" \
           r"|s3-[a-zA-Z0-9-\.\_\/]+" \
           r"|s3.amazonaws.com/[a-zA-Z0-9-\.\_]+" \
           r"|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\.\_]+)",
    'facebook_access_token' : r'EAACEdEose0cBA[0-9A-Za-z]+',
    'authorization_basic' : r'basic [a-zA-Z0-9=:_\+\/-]{5,100}',
    'authorization_bearer' : r'bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}',
    'mailgun_api_key' : r'key-[0-9a-zA-Z]{32}',
    'twilio_api_key' : r'SK[0-9a-fA-F]{32}',
    'twilio_account_sid' : r'AC[a-zA-Z0-9_\-]{32}',
    'twilio_app_sid' : r'AP[a-zA-Z0-9_\-]{32}',
    'paypal_braintree_access_token' : r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
    'square_oauth_secret' : r'sq0csp-[ 0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}',
    'square_access_token' : r'sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}',
    'stripe_standard_api' : r'sk_live_[0-9a-zA-Z]{24}',
    'stripe_restricted_api' : r'rk_live_[0-9a-zA-Z]{24}',
    'github_access_token' : r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*',
    'rsa_private_key' : r'-----BEGIN RSA PRIVATE KEY-----',
    'ssh_dsa_private_key' : r'-----BEGIN DSA PRIVATE KEY-----',
    'ssh_dc_private_key' : r'-----BEGIN EC PRIVATE KEY-----',
    'pgp_private_block' : r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
    'json_web_token' : r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$',
    'slack_token' : r"\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\"",
    'SSH_privKey' : r"([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)",
    'Heroku API KEY' : r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
}

class checker:
    def get_elements(self, tag_name, attribute):
        """
            Return elements in xml files which match with the tag name and the specific attribute
            :param tag_name: a string which specify the tag name
            :param attribute: a string which specify the attribute
        """
        l = []
        for i in self.xml:
            for item in self.xml[i].getElementsByTagName(tag_name):
                value = item.getAttributeNS(NS_ANDROID_URI, attribute)
                value = self.format_value( value )


                l.append( str( value ) )
        return l



    '''def get_element(self, tag_name, attribute):
        """
            Return element in xml files which match with the tag name and the specific attribute
            :param tag_name: specify the tag name
            :type tag_name: string
            :param attribute: specify the attribute
            :type attribute: string
            :rtype: string
        """
        for i in self.xml:
            for item in self.xml[i].getElementsByTagName(tag_name):
                value = item.getAttributeNS(NS_ANDROID_URI, attribute)

                if len(value) > 0:
                    return value
        return None


    def is_adb_backup_enabled(obj):
        """
            Return true if the APK can be backed up
            :rtype: boolean
        """
        adb_backup = obj.get_element("application", "allowBackup")
        if adb_backup is None:
            #If the default value is not set, the default is True.
            return True
        else:
            if adb_backup.lower() == 'true':
                return True 
            else:
                return False'''

    def backup_enabled(path_to_android_xml, tag_name, attribute):
        NS_ANDROID_URI = 'http://schemas.android.com/apk/res/android'
        obj = minidom.parse(path_to_android_xml)
        for item in obj.getElementsByTagName(tag_name):
            value = item.getAttributeNS(NS_ANDROID_URI, attribute)
            print(value)
            if len(value) > 0:
                adb_backup = value
        if adb_backup is None:
            #If the default value is not set, the default is True.
            return True
        else:
            if adb_backup.lower() == 'true':
                return True 
            else:
                return False
    
    #look for secret in .xml files
    def scan_for_secrets(output_dir, verbose=False):
        secrets_found = False
        found_secrets = {}
        for root, _, files in os.walk(output_dir):
            for filename in files:
                if filename.endswith('.xml'):
                    full_path = os.path.join(root, filename)
                    with open(full_path, 'r', encoding="utf-8") as f:
                        lines = f.readlines()
                        content = ''.join(lines)
                        for key, pattern in regex.items():
                            matches = re.finditer(pattern, content)
                            for match in matches:
                                secret_value = match.group()
                                line_number = content.count('\n', 0, match.start()) + 1
                                code_snippet = lines[line_number - 1].strip()
                                
                                if key not in found_secrets:
                                    found_secrets[key] = []
                                
                                found_secrets[key].append({
                                    "key": key,
                                    'value': secret_value,
                                    'line_number': line_number,
                                    'code_snippet': code_snippet,
                                    'file_path': full_path
                                })
                                
                                secrets_found = True
        
        if verbose:
            if secrets_found:
                print("Found the following secrets:")
                for key, matches in found_secrets.items():
                    print(f"{key}:")
                    for match_info in matches:
                        print(f"  Value: {match_info['value']}")
                        print(f"  File Path: {match_info['file_path']}")
                        print(f"  Line Number: {match_info['line_number']}")
                        print(f"  Code Snippet: {match_info['code_snippet']}\n")
            else:
                print("No secrets found in any files.")
        
        secrets_list = []
        for key, matches in found_secrets.items():
            for match_info in matches:
                secret_data = {
                    "key":key,
                    'value': match_info['value'],
                    'file_path': match_info['file_path'],
                    'line_number': match_info['line_number'],
                    'code_snippet': match_info['code_snippet']
                }
                secrets_list.append(secret_data)

        return secrets_list
