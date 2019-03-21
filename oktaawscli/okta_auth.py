""" Handles auth to Okta and returns SAML assertion """
# pylint: disable=C0325,R0912,C1801
import sys
import time
import requests
import logging

from bs4 import BeautifulSoup as bs

try:
    from u2flib_host import u2f, exc
    from u2flib_host.constants import APDU_WRONG_DATA
    U2F_ALLOWED = True
except ImportError:
    U2F_ALLOWED = False

try:
    input = raw_input
except NameError:
    pass


class OktaAuth():
    """ Handles auth to Okta and returns SAML assertion """
    def __init__(self, okta_profile, verbose, logger, totp_token, okta_auth_config):
        self.okta_profile = okta_profile
        self.totp_token = totp_token
        self.logger = logger
        self.factor = ""
        self.verbose = verbose
        self.https_base_url = "https://%s" % okta_auth_config.base_url_for(okta_profile)
        self.username = okta_auth_config.username_for(okta_profile)
        self.password = okta_auth_config.password_for(okta_profile)
        self.factor = okta_auth_config.factor_for(okta_profile)
        self.app_link = okta_auth_config.app_link_for(okta_profile)
        self.okta_auth_config = okta_auth_config

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
            elif resp_json['status'] == 'MFA_ENROLL':
                self.logger.warning("""MFA not enrolled. Cannot continue.
Please enroll a MFA factor in the Okta Web UI first!""")
                exit(2)
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
        if U2F_ALLOWED:
            supported_factor_types.append("u2f")

        supported_factors = []
        for factor in factors_list:
            if factor['factorType'] in supported_factor_types:
                supported_factors.append(factor)
            else:
                self.logger.info("Unsupported factorType: %s" %
                                 (factor['factorType'],))

        supported_factors = sorted(supported_factors,
                                   key=lambda factor: (
                                       factor['provider'],
                                       factor['factorType']))
        if len(supported_factors) == 1:
            session_token = self.verify_single_factor(
                supported_factors[0], state_token)
        elif len(supported_factors) > 0:
            if not self.factor:
                self.logger.info("Registered MFA factors:")
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
                elif factor_provider == "FIDO":
                        factor_name = "u2f"
                else:
                    factor_name = "Unsupported factor type: %s" % factor_provider

                if self.factor:
                    if self.factor == factor_provider:
                        factor_choice = index
                        self.logger.info("Using pre-selected factor choice \
                                         from ~/.okta-aws")
                        break
                else:
                    self.logger.debug("%d: %s" % (index + 1, factor_name))
            if not self.factor:
                factor_choice = int(input('Please select the MFA factor: ')) - 1
            self.logger.info("Performing secondary authentication using: %s" %
                             supported_factors[factor_choice]['provider'])
            session_token = self.verify_single_factor(supported_factors[factor_choice],
                                                      state_token)
        else:
            self.logger.error("MFA required, but no supported factors enrolled! Exiting.")
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
            elif resp_json['status'] == "MFA_CHALLENGE" and factor['factorType'] !='u2f':
                self.logger.info("Waiting for push verification...")
                while True:
                    resp = requests.post(
                        resp_json['_links']['next']['href'], json=req_data)
                    resp_json = resp.json()
                    if resp_json['status'] == 'SUCCESS':
                        return resp_json['sessionToken']
                    elif resp_json['factorResult'] == 'TIMEOUT':
                        self.logger.warning("Verification timed out")
                        exit(1)
                    elif resp_json['factorResult'] == 'REJECTED':
                        self.logger.error("Verification was rejected")
                        exit(1)
                    else:
                        time.sleep(0.5)

            if factor['factorType'] == 'u2f':
                devices = u2f.list_devices()
                if len(devices) == 0:
                    self.logger.warning("No U2F device found")
                    exit(1)

                challenge = dict()
                challenge['appId'] = resp_json['_embedded']['factor']['profile']['appId']
                challenge['version'] = resp_json['_embedded']['factor']['profile']['version']
                challenge['keyHandle'] = resp_json['_embedded']['factor']['profile']['credentialId']
                challenge['challenge'] = resp_json['_embedded']['factor']['_embedded']['challenge']['nonce']

                self.logger.info("Please touch your U2F device...")
                auth_response = None
                while not auth_response:
                    for device in devices:
                        with device as dev:
                            try:
                                auth_response = u2f.authenticate(dev, challenge, resp_json['_embedded']['factor']['profile']['appId'] )
                                req_data.update(auth_response)
                                resp = requests.post(resp_json['_links']['next']['href'], json=req_data)
                                resp_json = resp.json()
                                if resp_json['status'] == 'SUCCESS':
                                    return resp_json['sessionToken']
                                elif resp_json['factorResult'] == 'TIMEOUT':
                                    self.logger.warning("Verification timed out")
                                    exit(1)
                                elif resp_json['factorResult'] == 'REJECTED':
                                    self.logger.warning("Verification was rejected")
                                    exit(1)
                            except exc.APDUError as e:
                                if e.code == APDU_WRONG_DATA:
                                    devices.remove(device)
                                time.sleep(0.1)

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
        app_choice = 0 if len(aws_apps) == 1 else None
        if app_choice is None:
            print("Available apps:")
            for index, app in enumerate(aws_apps):
                app_name = app['label']
                print("%d: %s" % (index + 1, app_name))

            app_choice = int(input('Please select AWS app: ')) - 1
        self.logger.debug("Selected app: %s" % aws_apps[app_choice]['label'])
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
        if not self.app_link:
            app_name, app_link = self.get_apps(session_id)
            self.okta_auth_config.save_chosen_app_link_for_profile(self.okta_profile, app_link)
        else:
            app_name = None
            app_link = self.app_link
        sid = "sid=%s" % session_id
        headers = {'Cookie': sid}
        resp = requests.get(app_link, headers=headers)
        assertion = self.get_saml_assertion(resp)
        return app_name, assertion
