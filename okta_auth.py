""" Handles auth to Okta and returns SAML assertion """
from ConfigParser import RawConfigParser
import requests

class OktaAuth(object):
    """ Handles auth to Okta and returns SAML assertion """
    def __init__(self):
        parser = RawConfigParser()
        parser.read('.okta-aws')
        profile = "test"
        self.base_url = "https://%s" % parser.get(profile, 'base-url')
        self.username = parser.get(profile, 'username')
        self.password = parser.get(profile, 'password')

    def verify_single_factor(self, factor_id, state_token):
        """ Verifies a single MFA factor """
        factor_answer = input('Enter MFA token: ')
        req_data = {
            "stateToken": state_token,
            "answer": factor_answer
        }
        post_url = "%s/api/v1/authn/factors/%s/verify" % (self.base_url, factor_id)
        resp = requests.post(post_url, json=req_data)
        print resp.json()


    def verify_mfa(self, factors_list, state_token):
        """ Performs MFA auth against Okta """
        if len(factors_list) == 1:
            self.verify_single_factor(factors_list[0]['id'], state_token)
        else:
            print "Registered MFA factors: "

            for index, factor in enumerate(factors_list):
                if factor['provider'] == "GOOGLE":
                    factor_name = "Google Authenticator"
                elif factor['provider'] == "OKTA":
                    if factor['factorType'] == "push":
                        factor_name == "Okta Verify - Push"
                    else:
                        factor_name == "Okta Verify"
                else:
                    factor_name = "Unsupported factor type: %s" % factor['provider']


                print "%d - %s"%(index+1, factor_name)
            factor_choice = input('Please select the MFA factor: ')-1

            print factors_list[factor_choice]['id']
            self.verify_single_factor(factors_list[factor_choice]['id'], state_token)


    def primary_auth(self):
        """ Performs primary auth against Okta """

        auth_data = {
            "username": self.username,
            "password": self.password
        }
        resp = requests.post(self.base_url+'/api/v1/authn', json=auth_data).json()

        if resp['status'] == 'MFA_REQUIRED':
            factors_list = resp['_embedded']['factors']
            state_token = resp['stateToken']
            self.verify_mfa(factors_list, state_token)
