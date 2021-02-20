import time
import sys
import requests
try:
    from u2flib_host import u2f, exc
    from u2flib_host.constants import APDU_WRONG_DATA
    U2F_ALLOWED = True
except ImportError:
    U2F_ALLOWED = False

class OktaAuthMfaBase():
    """ Handles base org Okta MFA """
    def __init__(self, logger, state_token, factor, totp_token=None):
        self.state_token = state_token
        self.logger = logger
        self.factor = factor
        self.totp_token = totp_token


    def verify_mfa(self, factors_list):
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
            session_token = self._verify_single_factor(supported_factors[0])
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
            session_token = self._verify_single_factor(supported_factors[factor_choice])
        else:
            print("MFA required, but no supported factors enrolled! sys.exiting.")
            sys.exit(1)
        return session_token

    def _verify_single_factor(self, factor):
        """ Verifies a single MFA factor """
        req_data = {
            "stateToken": self.state_token
        }

        self.logger.debug(factor)
        if factor['factorType'] == 'token:software:totp':
            if self.totp_token:
                self.logger.debug("Using TOTP token from command line arg")
                req_data['answer'] = self.totp_token
            else:
                req_data['answer'] = input('Enter MFA verification code: ')

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
                    elif resp_json['status'] == 'PASSWORD_EXPIRED':
                        print("Your Okta password is expired")
                        sys.exit(1)
                    elif resp_json['factorResult'] == 'TIMEOUT':
                        print("Verification timed out")
                        sys.exit(1)
                    elif resp_json['factorResult'] == 'REJECTED':
                        print("Verification was rejected")
                        sys.exit(1)
                    else:
                        time.sleep(0.5)

            if factor['factorType'] == 'u2f':
                devices = u2f.list_devices()
                if len(devices) == 0:
                    self.logger.warning("No U2F device found")
                    sys.exit(1)

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
                                    sys.exit(1)
                                elif resp_json['factorResult'] == 'REJECTED':
                                    self.logger.warning("Verification was rejected")
                                    sys.exit(1)
                            except exc.APDUError as ex:
                                if ex.code == APDU_WRONG_DATA:
                                    devices.remove(device)
                                time.sleep(0.1)

        elif resp.status_code != 200:
            self.logger.error(resp_json['errorSummary'])
            sys.exit(1)
        else:
            self.logger.error(resp_json)
            sys.exit(1)
        return None
