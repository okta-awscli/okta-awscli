""" Handles auth to Okta and returns SAML assertion """
# pylint: disable=C0325,R0912,C1801
# Incorporates flow auth code taken from https://github.com/Nike-Inc/gimme-aws-creds
import sys
import re
from codecs import decode
import requests
from bs4 import BeautifulSoup as bs
from oktaawscli.okta_auth_mfa_base import OktaAuthMfaBase
from oktaawscli.okta_auth_mfa_app import OktaAuthMfaApp
from oktaawscli.util import input


class OktaAuth():
    """ Handles auth to Okta and returns SAML assertion """
    def __init__(self, okta_profile, verbose, logger, totp_token, 
        okta_auth_config, username, password, verify_ssl=True):

        self.okta_profile = okta_profile
        self.totp_token = totp_token
        self.logger = logger
        self.verbose = verbose
        self.verify_ssl = verify_ssl
        self.factor = okta_auth_config.factor_for(okta_profile)
        self.app_link = okta_auth_config.app_link_for(okta_profile)
        self.okta_auth_config = okta_auth_config
        self.session = None
        self.session_token = ""
        self.session_id = ""
        self.https_base_url = "https://%s" % okta_auth_config.base_url_for(okta_profile)
        self.auth_url = "%s/api/v1/authn" % self.https_base_url

        if username:
            self.username = username
        else:
            self.username = okta_auth_config.username_for(okta_profile)

        if password:
            self.password = password
        else:
            self.password = okta_auth_config.password_for(okta_profile)

    def primary_auth(self):
        """ Performs primary auth against Okta """

        auth_data = {
            "username": self.username,
            "password": self.password
        }
        self.session = requests.Session()
        resp = self.session.post(self.auth_url, json=auth_data)
        resp_json = resp.json()
        self.cookies = resp.cookies
        if 'status' in resp_json:
            if resp_json['status'] == 'MFA_REQUIRED':
                factors_list = resp_json['_embedded']['factors']
                state_token = resp_json['stateToken']
                mfa_base = OktaAuthMfaBase(self.logger, state_token, self.factor, self.totp_token)
                session_token = mfa_base.verify_mfa(factors_list)
            elif resp_json['status'] == 'SUCCESS':
                session_token = resp_json['sessionToken']
            elif resp_json['status'] == 'MFA_ENROLL':
                self.logger.warning("""MFA not enrolled. Cannot continue.
Please enroll an MFA factor in the Okta Web UI first!""")
                sys.exit(2)
        elif resp.status_code != 200:
            self.logger.error(resp_json['errorSummary'])
            sys.exit(1)
        else:
            self.logger.error(resp_json)
            sys.exit(1)


        return session_token


    def get_session(self, session_token):
        """ Gets a session cookie from a session token """
        data = {"sessionToken": session_token}
        resp = self.session.post(
            self.https_base_url + '/api/v1/sessions', json=data).json()
        return resp['id']


    def get_apps(self, session_id):
        """ Gets apps for the user """
        sid = "sid=%s" % session_id
        headers = {'Cookie': sid}
        resp = self.session.get(
            self.https_base_url + '/api/v1/users/me/appLinks',
            headers=headers).json()
        aws_apps = []
        for app in resp:
            if app['appName'] == "amazon_aws":
                aws_apps.append(app)
        if not aws_apps:
            self.logger.error("No AWS apps are available for your user. \
                sys.exiting.")
            sys.exit(1)

        aws_apps = sorted(aws_apps, key=lambda app: app['sortOrder'])
        app_choice = 0 if len(aws_apps) == 1 else None
        if app_choice is None:
            print("Available apps:")
            for index, app in enumerate(aws_apps):
                app_name = app['label']
                print("%d: %s" % (index + 1, app_name))

            app_choice = int(input('Please select AWS app: ')) - 1
        self.logger.debug("Selected app: %s" % aws_apps[app_choice]['label'])
        return aws_apps[app_choice]['label'], aws_apps[app_choice]['linkUrl']


    def get_simple_assertion(self, html):
        soup = bs(html.text, "html.parser")
        for input_tag in soup.find_all('input'):
            if input_tag.get('name') == 'SAMLResponse':
                return input_tag.get('value')

        return None


    def get_mfa_assertion(self, html):
        soup = bs(html.text, "html.parser")
        if hasattr(soup.title, 'string') and re.match(".* - Extra Verification$", soup.title.string):
            state_token = decode(re.search(r"var stateToken = '(.*)';", html.text).group(1), "unicode-escape")
        else:
            self.logger.error("No Extra Verification")
            return None

        self.session.cookies['oktaStateToken'] = state_token

        mfa_app = OktaAuthMfaApp(self.logger, self.session, self.verify_ssl, self.auth_url)
        api_response = mfa_app.stepup_auth(self.auth_url, state_token)
        resp = self.session.get(self.app_link)

        return self.get_saml_assertion(resp)


    def get_saml_assertion(self, html):
        """ Returns the SAML assertion from HTML """
        assertion = self.get_simple_assertion(html) or self.get_mfa_assertion(html)

        if not assertion:
            self.logger.error("SAML assertion not valid: " + assertion)
            sys.exit(-1)
        return assertion


    def get_assertion(self):
        """ Main method to get SAML assertion from Okta """
        self.session_token = self.primary_auth()
        self.session_id = self.get_session(self.session_token)
        if not self.app_link:
            app_name, self.app_link = self.get_apps(self.session_id)
            self.okta_auth_config.write_applink_to_profile(self.okta_profile, self.app_link)
        else:
            app_name = None
        self.session.cookies['sid'] = self.session_id
        resp = self.session.get(self.app_link)
        assertion = self.get_saml_assertion(resp)
        return app_name, assertion
