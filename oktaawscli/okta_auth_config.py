""" Config helper """

import os
from configparser import SafeConfigParser
from getpass import getpass, getuser

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
        self._value = SafeConfigParser(default_section='default')
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
            username = getuser()
            entered_username = input('Enter username [%s]: ' % username)
            username = username if entered_username == "" else entered_username
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

    def region_for(self, okta_profile):
        """ Gets region from config """
        if self._value.has_option(okta_profile, 'region'):
            region = self._value.get(okta_profile, 'region')
            self.logger.debug("Setting region to %s" % region)
            return region
        return 'us-east-1'

    def get_check_valid_creds(self, okta_profile):
        """ Gets if should check if AWS creds are valid from config """
        check_valid_creds = "True"
        if self._value.has_option(okta_profile, 'check-valid-creds'):
            check_valid_creds = self._value.get(okta_profile, 'check-valid-creds')

        self.logger.info("Check if credentials are valid: %s" % check_valid_creds)
        return check_valid_creds

    def get_store_role(self, okta_profile):
        """ Gets if should store role to okta-profile from config """
        store_role = "True"
        if self._value.has_option(okta_profile, 'store-role'):
            store_role = self._value.get(okta_profile, 'store-role')

        self.logger.info("Should store role: %s" % store_role)
        return store_role

    def get_auto_write_profile(self, okta_profile):
        """ Gets if should auto write aws creds to ~/.aws/credentials from config """
        auto_write_profile = "False"
        if self._value.has_option(okta_profile, 'auto-write-profile'):
            auto_write_profile = self._value.get(okta_profile, 'auto-write-profile')

        self.logger.info("Should write profile to ~/.aws/credentials: %s" % auto_write_profile)
        return auto_write_profile

    def get_session_duration(self, okta_profile):
        """ Gets STS session duration from config as an int"""
        session_duration = 3600 # AWS docs say default duration is 1 hour (3600 seconds)
        if self._value.has_option(okta_profile, 'session-duration'):
            session_duration = int(self._value.get(okta_profile, 'session-duration'))

        if session_duration > 43200 or session_duration < 3600:
            self.logger.info("Invalid session duration specified, defaulting to 1 hour.")
            session_duration = 3600

        self.logger.info("Configured session duration: %s seconds" % session_duration)
        return session_duration

    def save_chosen_role_for_profile(self, okta_profile, role_arn):
        """ Saves role to config """
        if not self._value.has_section(okta_profile):
            self._value.add_section(okta_profile)

        base_url = self.base_url_for(okta_profile)
        self._value.set(okta_profile, 'base-url', base_url)
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
