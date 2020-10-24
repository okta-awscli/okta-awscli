import time
import sys
from urllib.parse import parse_qs
from urllib.parse import urlparse
from oktaawscli.version import __version__

class OktaAuthMfaApp():
    """ Handles per-app Okta MFA """
    def __init__(self, logger, session, verify_ssl, auth_url):
        self.session = session
        self.logger = logger
        self._verify_ssl_certs = verify_ssl
        self._preferred_mfa_type = None
        self._mfa_code = None
        self._auth_url = auth_url


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
            sys.exit(2)

        status = login_data['status']

        if status == 'UNAUTHENTICATED':
            self.logger.error("You are not authenticated -- please try to log in again")
            sys.exit(2)
        elif status == 'LOCKED_OUT':
            self.logger.error("Your Okta access has been locked out due to failed login attempts.")
            sys.exit(2)
        elif status == 'MFA_ENROLL':
            self.logger.error("You must enroll in MFA before using this tool.")
            sys.exit(2)
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
            self._auth_url,
            json={'stateToken': state_token},
            headers=self._get_headers(),
            verify=self._verify_ssl_certs
        )

        return {'stateToken': state_token, 'apiResponse': response.json()}


    def _get_headers(self):
        return {
            'User-Agent': "okta-awscli/%s" % __version__,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }


    def _choose_factor(self, factors):
        """ gets a list of available authentication factors and
        asks the user to select the factor they want to use """

        print("Multi-factor Authentication required for application.")

        # filter the factor list down to just the types specified in preferred_mfa_type
        if self._preferred_mfa_type is not None:
            factors = list(filter(lambda item: item['factorType'] == self._preferred_mfa_type, factors))

        if len(factors) == 1:
            factor_name = self._build_factor_name(factors[0])
            self.logger.info("%s selected" % factor_name)
            selection = 0
        else:
            print("Pick a factor:")
            # print out the factors and let the user select
            for i, factor in enumerate(factors):
                factor_name = self._build_factor_name(factor)
                if factor_name:
                    print('[ %d ] %s' % (i, factor_name))
            selection = input("Selection: ")

        # make sure the choice is valid
        if int(selection) > len(factors):
            self.logger.error("You made an invalid selection")
            sys.exit(1)

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
            return "Unknown MFA type: " + factor['factorType']


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
        pass_code = self._mfa_code
        if pass_code is None:
            pass_code = input("Enter MFA verification code: ")
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
