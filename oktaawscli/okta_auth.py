""" Handles auth to Okta and returns SAML assertion """
#pylint: disable=C0325
import sys
import os
from ConfigParser import RawConfigParser
from getpass import getpass
from bs4 import BeautifulSoup as bs
import requests

class OktaAuth(object):
    """ Handles auth to Okta and returns SAML assertion """
    def __init__(self, okta_profile, verbose):
        home_dir = os.path.expanduser('~')
        okta_config = home_dir + '/.okta-aws'
        parser = RawConfigParser()
        parser.read(okta_config)
        profile = okta_profile
        if parser.has_option(profile, 'base-url'):
            self.base_url = "https://%s" % parser.get(profile, 'base-url')
        else:
            print("No base-url set in ~/.okta-aws")
        if parser.has_option(profile, 'username'):
            self.username = parser.get(profile, 'username')
            if verbose:
                print("Authenticating as: %s" % self.username)
        else:
            self.username = raw_input('Enter username: ')
        if parser.has_option(profile, 'password'):
            self.password = parser.get(profile, 'password')
        else:
            self.password = getpass('Enter password: ')
        self.verbose = verbose

    def primary_auth(self):
        """ Performs primary auth against Okta """

        auth_data = {
            "username": self.username,
            "password": self.password
        }
        resp = requests.post(self.base_url+'/api/v1/authn', json=auth_data)
        resp_json = resp.json()
        if 'status' in resp_json:
            if resp_json['status'] == 'MFA_REQUIRED':
                factors_list = resp_json['_embedded']['factors']
                state_token = resp_json['stateToken']
                session_token = self.verify_mfa(factors_list, state_token)
            elif resp_json['status'] == 'SUCCESS':
                session_token = resp_json['sessionToken']
        elif resp.status_code != 200:
            print(resp_json['errorSummary'])
            exit(1)
        else:
            print(resp_json)
            exit(1)

        return session_token

    def verify_mfa(self, factors_list, state_token):
        """ Performs MFA auth against Okta """
        if len(factors_list) == 1:
            session_token = self.verify_single_factor(factors_list[0]['id'], state_token)
        else:
            supported_factors = []
            for factor in factors_list:
                if factor['factorType'] == "token:software:totp":
                    supported_factors.append(factor)

            print("Registered MFA factors:")
            for index, factor in enumerate(supported_factors):
                factor_type = factor['factorType']
                factor_provider = factor['provider']

                if factor_provider == "GOOGLE":
                    factor_name = "Google Authenticator"
                elif factor_provider == "OKTA":
                    if factor_type == "push":
                        factor_name = "Okta Verify - Push"
                    else:
                        factor_name = "Okta Verify"
                else:
                    factor_name = "Unsupported factor type: %s" % factor_provider

                print("%d: %s" % (index+1, factor_name))
            factor_choice = input('Please select the MFA factor: ')-1
            session_token = self.verify_single_factor(factors_list[factor_choice]['id'],
                                                      state_token)
        return session_token

    def verify_single_factor(self, factor_id, state_token):
        """ Verifies a single MFA factor """
        factor_answer = raw_input('Enter MFA token: ')
        req_data = {
            "stateToken": state_token,
            "answer": factor_answer
        }
        post_url = "%s/api/v1/authn/factors/%s/verify" % (self.base_url, factor_id)
        resp = requests.post(post_url, json=req_data)
        resp_json = resp.json()
        if 'status' in resp_json:
            if resp_json['status'] == "SUCCESS":
                return resp_json['sessionToken']
        elif resp.status_code != 200:
            print(resp_json['errorSummary'])
            exit(1)
        else:
            print(resp_json)
            exit(1)


    def get_session(self, session_token):
        """ Gets a session cookie from a session token """
        data = {"sessionToken": session_token}
        resp = requests.post(self.base_url+'/api/v1/sessions', json=data).json()
        return resp['id']

    def get_apps(self, session_id):
        """ Gets apps for the user """
        sid = "sid=%s" % session_id
        headers = {'Cookie': sid}
        resp = requests.get(self.base_url+'/api/v1/users/me/appLinks', headers=headers).json()
        aws_apps = []
        for app in resp:
            if app['appName'] == "amazon_aws":
                aws_apps.append(app)
        if not aws_apps:
            print("No AWS apps are available for your user. Exiting.")
            sys.exit(1)
        print("Available apps:")
        for index, app in enumerate(aws_apps):
            app_name = app['label']
            print("%d: %s" % (index+1, app_name))

        app_choice = input('Please select AWS app: ')-1
        return aws_apps[app_choice]['label'], aws_apps[app_choice]['linkUrl']

    @staticmethod
    def get_saml_assertion(html):
        """ Returns the SAML assertion from HTML """
        soup = bs(html.text, "html.parser")
        assertion = ''

        for input_tag in soup.find_all('input'):
            if input_tag.get('name') == 'SAMLResponse':
                assertion = input_tag.get('value')

        if not assertion:
            print("SAML assertion not valid: " + assertion)
            exit(-1)
        return assertion

    def get_assertion(self):
        """ Main method to get SAML assertion from Okta """
        session_token = self.primary_auth()
        session_id = self.get_session(session_token)
        app_name, app_link = self.get_apps(session_id)
        sid = "sid=%s" % session_id
        headers = {'Cookie': sid}
        resp = requests.get(app_link, headers=headers)
        assertion = self.get_saml_assertion(resp)
        return app_name, assertion
