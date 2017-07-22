""" Handles auth to Okta and returns SAML assertion """
from ConfigParser import SafeConfigParser
import requests

class OktaAuth(object):
    """ Handles auth to Okta and returns SAML assertion """
    def __init__(self):
        parser = SafeConfigParser()
        parser.read('.okta-aws')
        profile = "default"
        self.base_url = "https://%s" % parser.get(profile, 'base-url')
        self.username = parser.get(profile, 'username')
        self.password = parser.get(profile, 'password')


    def verify_mfa(self, factors_list, state_token):
        """ Performs MFA auth against Okta """
        factor_providers = {
            'OTKA': 'Okta Verify',
            'GOOGLE': 'Google Authenticator',
            'FIDO': 'FIDO U2F Security Token'
        }

        print "Please choose: "
        for factor in factors_list:
            push_text = ""
            if factor['factorType'] == "push":
                push_text = " push notification"
            print factor_providers[factor['provider']] + push_text

        # if factor['factorType'] == 'token:software:totp':
        #     pass ##Prompt for factor_answer
        # else:
        #     pass ##Not Supported

        # req_data = {
        #     "stateToken": state_token,
        #     "answer": factor_answer
        # }
        # factor_id = 'uftaxd3nkzWLDDain0h7'
        # resp = requests.post(self.base_url+'/api/v1/authn/factors/%s/verify',
        #                      json=req_data) % factor_id
        # print resp.json()

    def primary_auth(self):
        """ Performs primary auth against Okta """

        auth_data = {
            "username": self.username,
            "password": self.password
        }
        resp = requests.post(self.base_url+'/api/v1/authn', json=auth_data).json()
        print resp

        if resp['status'] == 'MFA_REQUIRED':
            factors_list = resp['_embedded']['factors']
            state_token = resp['stateToken']
            self.verify_mfa(factors_list, state_token)
