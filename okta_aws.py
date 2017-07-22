""" Wrapper script for awscli which handles Okta auth """
from okta_auth import OktaAuth

def main():
    """ Main entrypoint """
    okta = OktaAuth()
    okta.primary_auth()

if __name__ == "__main__":
    main()
