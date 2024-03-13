import time
import sys
import base64
import traceback

import requests

try:
    from u2flib_host import u2f, exc
    from u2flib_host.constants import APDU_WRONG_DATA
    U2F_ALLOWED = True
except ImportError:
    U2F_ALLOWED = False


try:
    from typing import Any
    from functools import reduce
    from fido2.hid import CtapHidDevice
    from fido2.utils import websafe_decode
    from fido2.webauthn import (
        PublicKeyCredentialDescriptor,
        PublicKeyCredentialRequestOptions,
        PublicKeyCredentialType,
        UserVerificationRequirement,
    )
    from fido2.client import Fido2Client
    from getpass import getpass
    from typing import Optional
    from fido2.client import UserInteraction
    from fido2.ctap2.pin import ClientPin
    WEBAUTHN_ALLOWED = True
except ImportError:
    WEBAUTHN_ALLOWED = False

def v(d: dict[str, Any], key: str, default: Any = "") -> Any:
    parts = key.split(".")
    prop = parts[-1]
    path = parts[:-1]

    child = reduce(
        lambda acc, v: acc.get(v, {}),
        path,
        d,
    )

    return child.get(prop, default)

class OktaAuthMfaBase():
    """ Handles base org Okta MFA """
    def __init__(self, logger, state_token, factor, totp_token=None, base_url=None):
        self.state_token = state_token
        self.logger = logger
        self.factor = factor
        self.totp_token = totp_token
        self.base_url = base_url
        self.https_base_url = "https://%s" % base_url


    def verify_mfa(self, factors_list):
        """ Performs MFA auth against Okta """

        supported_factor_types = ["token:software:totp", "push"]
        if U2F_ALLOWED:
            supported_factor_types.append("u2f")
        if WEBAUTHN_ALLOWED:
            supported_factor_types.append("webauthn")

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

        if self.factor and not self.factor in [factor['provider'] for factor in supported_factors]:
            self.logger.error("Unable to locate selected factor type {}".format(self.factor))
            sys.exit(1)

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

                factor_name = factor['factorType'] + ": " + (factor['profile'].get('authenticatorName') or factor['factorType'])

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
            elif resp_json['status'] == "MFA_CHALLENGE" and factor['factorType'] !='u2f' and factor['factorType'] !='webauthn':
                print("Waiting for push verification...")
                correct_answer_shown = False
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
                        if not correct_answer_shown:
                            try:
                                correct_answer = resp_json['_embedded']['factor']['_embedded']['challenge']['correctAnswer']
                                if correct_answer:
                                    print(f'On your phone, tap {correct_answer} in the Okta Verify app')
                                    correct_answer_shown = True
                            except KeyError:
                                pass
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

            if factor['factorType'] == 'webauthn' and factor['provider'] == 'FIDO':
                class CliInteraction(UserInteraction):
                    def __init__(self, user_interaction_msg):
                        self.user_interaction_msg = user_interaction_msg

                    def prompt_up(self) -> None:
                        print(self.user_interaction_msg)

                    def request_pin(
                        self, _: ClientPin.PERMISSION, rp_id: Optional[str]
                    ) -> Optional[str]:
                        return getpass(f"Enter PIN to authenticate in {rp_id}: ")

                    def request_uv(self, unused, unused_) -> bool:
                        print("User Verification required.")
                        return True

                user_verification = UserVerificationRequirement.DISCOURAGED
                devices = list(CtapHidDevice.list_devices())
                # Support for 'Touch ID' on macOS
                if sys.platform == "darwin":
                    from ctap_keyring_device.ctap_keyring_device import CtapKeyringDevice
                    from ctap_keyring_device.ctap_strucs import CtapOptions
                    # devices = devices + CtapKeyringDevice.list_devices()  # this is too noisy!
                    # Dirty hack to detect that 'Touch ID' is being requested
                    print("[DEBUG]", factor)
                    if (factor["profile"]["authenticatorName"] is None) and ("yubi" not in ("%s" % factor["profile"]["authenticatorName"]).lower()):
                        print("[DEBUG] - Invoking CtapKeyringDevice.list_devices() stuff...")
                        devices = CtapKeyringDevice.list_devices()  # only try the 'Touch ID'
                        print("[DEBUG]", devices)
                if len(devices) == 0:
                    self.logger.warning("No U2F device found. Exiting...")
                    exit(1)
                challenge = v(resp_json, '_embedded.factor._embedded.challenge.challenge')
                challenge_b = websafe_decode(challenge)
                credentialId = websafe_decode(v(resp_json,'_embedded.factor.profile.credentialId'))

                result = None
                while not result:
                    for dev in devices:
                        if isinstance(dev, CtapHidDevice):
                            user_verification = UserVerificationRequirement.REQUIRED
                        else:
                            user_verification = UserVerificationRequirement.DISCOURAGED
                        client = Fido2Client(dev, self.https_base_url)
                        user_interaction_msg = (
                            '!!! Touch the selected MFA device on your macOS laptop... !!!'
                            if sys.platform == "darwin"
                            else '!!! Touch the flashing U2F device to authenticate... !!!'
                        )
                        client = Fido2Client(
                            device=dev,
                            origin=self.https_base_url,
                            user_interaction=CliInteraction(user_interaction_msg),
                        )
                        user_verification = (
                            UserVerificationRequirement.REQUIRED
                            if client.info.options.get('clientPin', False)
                            else UserVerificationRequirement.DISCOURAGED
                        )
                        request = PublicKeyCredentialRequestOptions(
                            challenge=challenge_b,
                            timeout=100000,
                            rp_id=self.base_url,
                            allow_credentials=[
                                PublicKeyCredentialDescriptor(
                                    type=PublicKeyCredentialType.PUBLIC_KEY ,
                                    id=credentialId
                                )
                            ],
                            user_verification=user_verification,
                        )
                        try:
                            result = client.get_assertion(request)
                            assertion = result.get_response(0)
                            self.logger.debug('assertion.result: %s', result)
                            b64authenticatorData = (base64.b64encode(assertion.authenticator_data)).decode('ascii')
                            b64clientData = assertion.client_data.b64
                            b64signatureData = (base64.b64encode(assertion.signature)).decode('ascii')
                            okta_response = {
                                'authenticatorData': b64authenticatorData,
                                'clientData': b64clientData,
                                'signatureData': b64signatureData
                            }
                            req_data.update(okta_response)
                            resp = requests.post(v(resp_json,'_links.next.href'), json=req_data)
                            resp_json = resp.json()
                            if resp_json['status'] == 'SUCCESS':
                                return resp_json['sessionToken']
                            elif resp_json['factorResult'] == 'TIMEOUT':
                                self.logger.warning("Verification timed out")
                                exit(1)
                            elif resp_json['factorResult'] == 'REJECTED':
                                self.logger.warning("Verification was rejected")
                                exit(1)
                            # break
                        except Exception:
                            traceback.print_exc(file=sys.stderr)
                            result = None
                    if not result:
                        return None

        elif resp.status_code != 200:
            self.logger.error(resp_json['errorSummary'])
            sys.exit(1)
        else:
            self.logger.error(resp_json)
            sys.exit(1)
        return None
