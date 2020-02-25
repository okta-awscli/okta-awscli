""" Handles auth to Okta and returns SAML assertion """
# pylint: disable=C0325,R0912,C1801
# Incorporates flow auth code taken from https://github.com/Nike-Inc/gimme-aws-creds
import sys
import time
import requests
import re
from codecs import decode
from urllib.parse import parse_qs
from urllib.parse import urlparse

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
        self._verify_ssl_certs = True
        self._preferred_mfa_type = None
        self._mfa_code = None
        self.https_base_url = "https://%s" % okta_auth_config.base_url_for(okta_profile)
        self.username = okta_auth_config.username_for(okta_profile)
        self.password = okta_auth_config.password_for(okta_profile)
        self.factor = okta_auth_config.factor_for(okta_profile)
        self.app_link = okta_auth_config.app_link_for(okta_profile)
        self.okta_auth_config = okta_auth_config
        self.session = None
        self.session_token = ""
        self.session_id = ""

    def primary_auth(self):
        """ Performs primary auth against Okta """

        auth_data = {
            "username": self.username,
            "password": self.password
        }
        self.session = requests.Session()
        resp = self.session.post(self.https_base_url + '/api/v1/authn', json=auth_data)
        resp_json = resp.json()
        self.cookies = resp.cookies
        if 'status' in resp_json:
            if resp_json['status'] == 'MFA_REQUIRED':
                factors_list = resp_json['_embedded']['factors']
                state_token = resp_json['stateToken']
                session_token = self.verify_mfa(factors_list, state_token)
            elif resp_json['status'] == 'SUCCESS':
                session_token = resp_json['sessionToken']
            elif resp_json['status'] == 'MFA_ENROLL':
                self.logger.warning("""MFA not enrolled. Cannot continue.
Please enroll an MFA factor in the Okta Web UI first!""")
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
                self.logger.error("Unsupported factorType: %s" %
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
                    print("%d: %s" % (index + 1, factor_name))
            if not self.factor:
                factor_choice = int(input('Please select the MFA factor: ')) - 1
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
            elif resp_json['status'] == "MFA_CHALLENGE" and factor['factorType'] !='u2f':
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

                print("Please touch your U2F device...")
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
        self.session.cookies['mp_Account Settings__c'] = '0'
        self.session.cookies['Okta_Verify_Autopush_2012557501'] = 'true'
        self.session.cookies['Okta_Verify_Autopush_-610254449'] = 'true'

        api_response = self.stepup_auth(self.https_base_url + '/api/v1/authn', state_token)
        resp = self.session.get(self.app_link)

        return self.get_saml_assertion(resp)

    def get_saml_assertion(self, html):
        """ Returns the SAML assertion from HTML """
        assertion = self.get_simple_assertion(html) or self.get_mfa_assertion(html)

        if not assertion:
            self.logger.error("SAML assertion not valid: " + assertion)
            exit(-1)
        return assertion

    def stepup_auth(self, embed_link, state_token=None):
        """ Login to Okta using the Step-up authentication flow"""
        flow_state = self._get_initial_flow_state(embed_link, state_token)

        while flow_state.get('apiResponse').get('status') != 'SUCCESS':
            flow_state = self._next_login_step(
                flow_state.get('stateToken'), flow_state.get('apiResponse'))

        return flow_state['apiResponse']

    def _next_login_step(self, state_token, login_data):
        """ decide what the next step in the login process is"""
        if 'errorCode' in login_data:
            self.logger.error("LOGIN ERROR: {} | Error Code: {}".format(login_data['errorSummary'], login_data['errorCode']))
            exit(2)

        status = login_data['status']

        if status == 'UNAUTHENTICATED':
            self.logger.error("You are not authenticated -- please try to log in again")
            exit(2)
        elif status == 'LOCKED_OUT':
            self.logger.error("Your Okta access has been locked out due to failed login attempts.")
            exit(2)
        elif status == 'MFA_ENROLL':
            self.logger.error("You must enroll in MFA before using this tool.")
            exit(2)
        elif status == 'MFA_REQUIRED':
            return self._login_multi_factor(state_token, login_data)
        elif status == 'MFA_CHALLENGE':
            if 'factorResult' in login_data and login_data['factorResult'] == 'WAITING':
                return self._check_push_result(state_token, login_data)
            else:
                return self._login_input_mfa_challenge(state_token, login_data['_links']['next']['href'])
        else:
            raise RuntimeError('Unknown login status: ' + status)


    def _get_initial_flow_state(self, embed_link, state_token=None):
        """ Starts the authentication flow with Okta"""
        if state_token is None:
            response = self.session.get(
                embed_link, allow_redirects=False)
            url_parse_results = urlparse(response.headers['Location'])
            state_token = parse_qs(url_parse_results.query)['stateToken'][0]

        response = self.session.post(
            self.https_base_url + '/api/v1/authn',
            json={'stateToken': state_token},
            headers=self._get_headers(),
            verify=self._verify_ssl_certs
        )

        return {'stateToken': state_token, 'apiResponse': response.json()}

    def _get_headers(self):
        return {
            'User-Agent': 'Okta-awscli/0.0.1',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }

    def get_assertion(self):
        """ Main method to get SAML assertion from Okta """
        self.session_token = self.primary_auth()
        self.session_id = self.get_session(self.session_token)
        if not self.app_link:
            app_name, self.app_link = self.get_apps(self.session_id)
            self.okta_auth_config.save_chosen_app_link_for_profile(self.okta_profile, self.app_link)
        else:
            app_name = None
        self.session.cookies['sid'] = self.session_id
        resp = self.session.get(self.app_link)
        assertion = self.get_saml_assertion(resp)
        return app_name, assertion

    def _login_send_sms(self, state_token, factor):
        """ Send SMS message for second factor authentication"""
        response = self.session.post(
            factor['_links']['verify']['href'],
            json={'stateToken': state_token},
            headers=self._get_headers(),
            verify=self._verify_ssl_certs
        )

        self.logger.info("A verification code has been sent to " + factor['profile']['phoneNumber'])
        response_data = response.json()

        if 'stateToken' in response_data:
            return {'stateToken': response_data['stateToken'], 'apiResponse': response_data}
        if 'sessionToken' in response_data:
            return {'stateToken': None, 'sessionToken': response_data['sessionToken'], 'apiResponse': response_data}

    def _login_send_call(self, state_token, factor):
        """ Send Voice call for second factor authentication"""
        response = self.session.post(
            factor['_links']['verify']['href'],
            json={'stateToken': state_token},
            headers=self._get_headers(),
            verify=self._verify_ssl_certs
        )

        self.logger.info("You should soon receive a phone call at " + factor['profile']['phoneNumber'])
        response_data = response.json()

        if 'stateToken' in response_data:
            return {'stateToken': response_data['stateToken'], 'apiResponse': response_data}
        if 'sessionToken' in response_data:
            return {'stateToken': None, 'sessionToken': response_data['sessionToken'], 'apiResponse': response_data}


    def _login_send_push(self, state_token, factor):
        """ Send 'push' for the Okta Verify mobile app """
        response = self.session.post(
            factor['_links']['verify']['href'],
            json={'stateToken': state_token},
            headers=self._get_headers(),
            verify=self._verify_ssl_certs
        )

        self.logger.info("Okta Verify push sent...")
        response_data = response.json()

        if 'stateToken' in response_data:
            return {'stateToken': response_data['stateToken'], 'apiResponse': response_data}
        if 'sessionToken' in response_data:
            return {'stateToken': None, 'sessionToken': response_data['sessionToken'], 'apiResponse': response_data}

    def _login_multi_factor(self, state_token, login_data):
        """ handle multi-factor authentication with Okta"""
        factor = self._choose_factor(login_data['_embedded']['factors'])
        if factor['factorType'] == 'sms':
            return self._login_send_sms(state_token, factor)
        elif factor['factorType'] == 'call':
            return self._login_send_call(state_token, factor)
        elif factor['factorType'] == 'token:software:totp':
            return self._login_input_mfa_challenge(state_token, factor['_links']['verify']['href'])
        elif factor['factorType'] == 'token':
            return self._login_input_mfa_challenge(state_token, factor['_links']['verify']['href'])
        elif factor['factorType'] == 'push':
            return self._login_send_push(state_token, factor)

    def _login_input_mfa_challenge(self, state_token, next_url):
        """ Submit verification code for SMS or TOTP authentication methods"""
        pass_code = self._mfa_code;
        if pass_code is None:
            pass_code = input("Enter verification code: ")
        response = self.session.post(
            next_url,
            json={'stateToken': state_token, 'passCode': pass_code},
            headers=self._get_headers(),
            verify=self._verify_ssl_certs
        )

        response_data = response.json()
        if 'status' in response_data and response_data['status'] == 'SUCCESS':
            if 'stateToken' in response_data:
                return {'stateToken': response_data['stateToken'], 'apiResponse': response_data}
            if 'sessionToken' in response_data:
                return {'stateToken': None, 'sessionToken': response_data['sessionToken'], 'apiResponse': response_data}
        else:
            return {'stateToken': None, 'sessionToken': None, 'apiResponse': response_data}

    def _check_push_result(self, state_token, login_data):
        """ Check Okta API to see if the push request has been responded to"""
        time.sleep(1)
        response = self.session.post(
            login_data['_links']['next']['href'],
            json={'stateToken': state_token},
            headers=self._get_headers(),
            verify=self._verify_ssl_certs
        )

        response_data = response.json()
        if 'stateToken' in response_data:
            return {'stateToken': response_data['stateToken'], 'apiResponse': response_data}
        if 'sessionToken' in response_data:
            return {'stateToken': None, 'sessionToken': response_data['sessionToken'], 'apiResponse': response_data}

    def _choose_factor(self, factors):
        """ gets a list of available authentication factors and
        asks the user to select the factor they want to use """

        print("Multi-factor Authentication required.")

        # filter the factor list down to just the types specified in preferred_mfa_type
        if self._preferred_mfa_type is not None:
            factors = list(filter(lambda item: item['factorType'] == self._preferred_mfa_type, factors))

        if len(factors) == 1:
            factor_name = self._build_factor_name(factors[0])
            self.logger.info(factor_name, 'selected')
            selection = 0
        else:
            print("Pick a factor:")
            # print out the factors and let the user select
            for i, factor in enumerate(factors):
                factor_name = self._build_factor_name(factor)
                if factor_name is not "":
                    print('[ %d ] %s' % (i, factor_name))
            selection = input("Selection: ")

        # make sure the choice is valid
        if int(selection) > len(factors):
            self.logger.error("You made an invalid selection")
            exit(1)

        return factors[int(selection)]

    @staticmethod
    def _build_factor_name(factor):
        """ Build the display name for a MFA factor based on the factor type"""
        if factor['factorType'] == 'push':
            return "Okta Verify App: " + factor['profile']['deviceType'] + ": " + factor['profile']['name']
        elif factor['factorType'] == 'sms':
            return factor['factorType'] + ": " + factor['profile']['phoneNumber']
        elif factor['factorType'] == 'call':
            return factor['factorType'] + ": " + factor['profile']['phoneNumber']
        elif factor['factorType'] == 'token:software:totp':
            return factor['factorType'] + "( " + factor['provider'] + " ) : " + factor['profile']['credentialId']
        elif factor['factorType'] == 'token':
            return factor['factorType'] + ": " + factor['profile']['credentialId']
        else:
            return ("Unknown MFA type: " + factor['factorType'])
