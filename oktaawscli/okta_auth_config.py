""" Config helper """

import os

from configparser import RawConfigParser
from getpass import getpass

try:
    input = raw_input
except NameError:
    pass


class OktaAuthConfig():
    """ Config helper class """
    def __init__(self, logger, reset):
        self.logger = logger
        self.reset = reset
        self.config_path = os.path.expanduser('~') + '/.okta-aws'
        self._value = RawConfigParser()
        self._value.read(self.config_path)

    def base_url_for(self, okta_profile):
        """ Gets base URL from config """
        if self._value.has_option(okta_profile, 'base-url'):
            base_url = self._value.get(okta_profile, 'base-url')
            self.logger.info("Authenticating to: %s" % base_url)
        else:
            base_url = self._value.get('default', 'base-url')
            self.logger.info("Using base-url from default profile %s" % base_url)
        return base_url

    def username_for(self, okta_profile):
        """ Gets username from config """
        if self._value.has_option(okta_profile, 'username') and not self.reset:
            username = self._value.get(okta_profile, 'username')
            self.logger.info("Authenticating as: %s" % username)
        else:
            username = input('Enter username: ')
        return username

    def password_for(self, okta_profile):
        """ Gets password from config """
        if self._value.has_option(okta_profile, 'password'):
            password = self._value.get(okta_profile, 'password')
        else:
            password = getpass('Enter password: ')
        return password

    def factor_for(self, okta_profile):
        """ Gets factor from config """
        if self._value.has_option(okta_profile, 'factor') and not self.reset:
            factor = self._value.get(okta_profile, 'factor')
            self.logger.debug("Setting MFA factor to %s" % factor)
            return factor
        return None

    def app_for(self, okta_profile):
        """ Gets app from config """
        if self._value.has_option(okta_profile, 'app') and not self.reset:
            app = self._value.get(okta_profile, 'app')
            self.logger.debug("Setting app to %s" % app)
            return app
        return None

    def get_profile_alias(self, okta_profile):
        """ Gets if should use alias as profile from config """
        use_alias_as_profile = "False"
        if self._value.has_option(okta_profile, 'use-alias-profile'):
            use_alias_as_profile = self._value.get(okta_profile, 'use-alias-profile')
        else:
            use_alias_as_profile = self._value.get('default', 'use-alias-profile')
        self.logger.info("Use alias as profile: %s" % use_alias_as_profile)
        return use_alias_as_profile

    def save_chosen_role_for_profile(self, okta_profile, role_arn):
        """ Saves role to config """
        if not self._value.has_section(okta_profile):
            self._value.add_section(okta_profile)

        base_url = self.base_url_for(okta_profile)
        self._value.set(okta_profile, 'base-url', base_url)
        if okta_profile != "default":
            self._value.set(okta_profile, 'role', role_arn)

        with open(self.config_path, 'w+') as configfile:
            self._value.write(configfile)

    def save_chosen_factor_for_profile(self, okta_profile, factor):
        """ Saves factor to config """
        if not self._value.has_section(okta_profile):
            self._value.add_section(okta_profile)

        self._value.set(okta_profile, 'factor', factor)

        with open(self.config_path, 'w+') as configfile:
            self._value.write(configfile)

    def save_chosen_app_for_profile(self, okta_profile, app):
        """ Saves app to config """
        if not self._value.has_section(okta_profile):
            self._value.add_section(okta_profile)

        self._value.set(okta_profile, 'app', app)

        with open(self.config_path, 'w+') as configfile:
            self._value.write(configfile)
