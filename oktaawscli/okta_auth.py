""" Handles auth to Okta and returns SAML assertion """
# pylint: disable=C0325,R0912,C1801
import sys
import time
import requests

from bs4 import BeautifulSoup as bs

try:
    input = raw_input
except NameError:
    pass


class OktaAuth():
    """ Handles auth to Okta and returns SAML assertion """
    def __init__(self, okta_profile, verbose, logger,
                 totp_token, okta_auth_config):
        self.okta_profile = okta_profile
        self.totp_token = totp_token
        self.logger = logger
        self.factor = ""
        self.verbose = verbose
        self.okta_auth_config = okta_auth_config
        self.https_base_url = "https://%s" % okta_auth_config.base_url_for(okta_profile)
        self.username = okta_auth_config.username_for(okta_profile)
        self.password = okta_auth_config.password_for(okta_profile)
        self.factor = okta_auth_config.factor_for(okta_profile)
        self.app = okta_auth_config.app_for(okta_profile)


    def primary_auth(self):
        """ Performs primary auth against Okta """

        auth_data = {
            "username": self.username,
            "password": self.password
        }
        resp = requests.post(self.https_base_url + '/api/v1/authn', json=auth_data)
        resp_json = resp.json()
        if 'status' in resp_json:
            if resp_json['status'] == 'MFA_REQUIRED':
                factors_list = resp_json['_embedded']['factors']
                state_token = resp_json['stateToken']
                session_token = self.verify_mfa(factors_list, state_token)
            elif resp_json['status'] == 'SUCCESS':
                session_token = resp_json['sessionToken']
        elif resp.status_code != 200:
            self.logger.error(resp_json['errorSummary'])
            exit(1)
        else:
            self.logger.error(resp_json)
            exit(1)

        return session_token

    def verify_mfa(self, factors_list, state_token):
        """ Performs MFA auth against Okta """

        supported_factor_types = ["token:software:totp", "push"]
        supported_factors = []
        for factor in factors_list:
            if factor['factorType'] in supported_factor_types:
                supported_factors.append(factor)
            else:
                self.logger.info("Unsupported factorType: %s" % (factor['factorType'],))

        supported_factors = sorted(supported_factors,
                                   key=lambda factor: (
                                       factor['provider'],
                                       factor['factorType']))
        if len(supported_factors) == 1:
            session_token = self.verify_single_factor(
                supported_factors[0], state_token)
        elif len(supported_factors) > 0:
            if not self.factor:
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

                if self.factor:
                    if self.factor == factor_provider:
                        factor_choice = index
                        self.logger.info("Using pre-selected factor choice \
                                         from ~/.okta-aws")
                        break
                else:
                    print("%d: %s" % (index + 1, factor_name))
            if not self.factor:
                factor_choice = int(input('Please select the MFA factor: ')) - 1
                self.okta_auth_config.save_chosen_factor_for_profile(self.okta_profile, supported_factors[factor_choice]['provider'])
            self.logger.info("Performing secondary authentication using: %s" %
                             supported_factors[factor_choice]['provider'])
            session_token = self.verify_single_factor(supported_factors[factor_choice],
                                                      state_token)
        else:
            print("MFA required, but no supported factors enrolled! Exiting.")
            exit(1)
        return session_token

    def verify_single_factor(self, factor, state_token):
        """ Verifies a single MFA factor """
        req_data = {
            "stateToken": state_token
        }

        self.logger.debug(factor)

        if factor['factorType'] == 'token:software:totp':
            if self.totp_token:
                self.logger.debug("Using TOTP token from command line arg")
                req_data['answer'] = self.totp_token
            else:
                req_data['answer'] = input('Enter MFA token: ')
        post_url = factor['_links']['verify']['href']
        resp = requests.post(post_url, json=req_data)
        resp_json = resp.json()
        if 'status' in resp_json:
            if resp_json['status'] == "SUCCESS":
                return resp_json['sessionToken']
            elif resp_json['status'] == "MFA_CHALLENGE":
                print("Waiting for push verification...")
                while True:
                    resp = requests.post(
                        resp_json['_links']['next']['href'], json=req_data)
                    resp_json = resp.json()
                    if resp_json['status'] == 'SUCCESS':
                        return resp_json['sessionToken']
                    elif resp_json['factorResult'] == 'TIMEOUT':
                        print("Verification timed out")
                        exit(1)
                    elif resp_json['factorResult'] == 'REJECTED':
                        print("Verification was rejected")
                        exit(1)
                    else:
                        time.sleep(0.5)
        elif resp.status_code != 200:
            self.logger.error(resp_json['errorSummary'])
            exit(1)
        else:
            self.logger.error(resp_json)
            exit(1)
        return None

    def get_session(self, session_token):
        """ Gets a session cookie from a session token """
        data = {"sessionToken": session_token}
        resp = requests.post(
            self.https_base_url + '/api/v1/sessions', json=data).json()
        return resp['id']

    def get_apps(self, session_id):
        """ Gets apps for the user """
        sid = "sid=%s" % session_id
        headers = {'Cookie': sid}
        resp = requests.get(
            self.https_base_url + '/api/v1/users/me/appLinks',
            headers=headers).json()
        aws_apps = []
        for app in resp:
            if app['appName'] == "amazon_aws":
                aws_apps.append(app)
        if not aws_apps:
            self.logger.error("No AWS apps are available for your user. \
                Exiting.")
            sys.exit(1)

        aws_apps = sorted(aws_apps, key=lambda app: app['sortOrder'])
        app_choice = None
        for index, app in enumerate(aws_apps):
            if self.app and app['label'] == self.app:
                app_choice = index
                break
            print("%d: %s" % (index + 1, app['label']))
        if app_choice is None:
            app_choice = int(input('Please select AWS app: ')) - 1
            self.okta_auth_config.save_chosen_app_for_profile(
                self.okta_profile,
                aws_apps[app_choice]['label']
            )

        return aws_apps[app_choice]['label'], aws_apps[app_choice]['linkUrl']

    def get_saml_assertion(self, html):
        """ Returns the SAML assertion from HTML """
        soup = bs(html.text, "html.parser")
        assertion = ''

        for input_tag in soup.find_all('input'):
            if input_tag.get('name') == 'SAMLResponse':
                assertion = input_tag.get('value')

        if not assertion:
            self.logger.error("SAML assertion not valid: " + assertion)
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
