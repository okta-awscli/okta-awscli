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
        base_url = self._value.get(okta_profile, 'base-url')
        self.logger.info("Authenticating to: %s" % base_url)
        return base_url

    def username_for(self, okta_profile):
        """ Gets username from config """
        username = self._value.get(okta_profile, 'username', fallback=None)
        if not username or self.reset:
            username = getuser()
            entered_username = input('Enter username [%s]: ' % username)
            username = entered_username or username
        self.logger.info("Authenticating as: %s" % username)
        return username

    def password_for(self, okta_profile):
        """ Gets password from config """
        password = self._value.get(okta_profile, 'password', fallback=None)
        if not password:
            password = getpass('Enter password: ')
        return password

    def factor_for(self, okta_profile):
        """ Gets factor from config """
        if self.reset:
            return None

        factor = self._value.get(okta_profile, 'factor', fallback=None)
        self.logger.debug("Setting MFA factor to %s" % factor)
        return factor

    def app_for(self, okta_profile):
        """ Gets app from config """
        if self.reset:
            return None

        app = self._value.get(okta_profile, 'app', fallback=None)
        self.logger.debug("Setting app to %s" % app)
        return app

    def region_for(self, okta_profile):
        """ Gets region from config """
        region = self._value.get(okta_profile, 'region', fallback="us-east-1")
        self.logger.debug("Setting region to %s" % region)
        return region

    def get_check_valid_creds(self, okta_profile):
        """ Gets if should check if AWS creds are valid from config """
        check_valid_creds = self._value.get(okta_profile, 'check-valid-creds', fallback="True")
        self.logger.info("Check if credentials are valid: %s" % check_valid_creds)
        return check_valid_creds

    def get_store_role(self, okta_profile):
        """ Gets if should store role to okta-profile from config """
        store_role = self._value.get(okta_profile, 'store-role', fallback="True")
        self.logger.info("Should store role: %s" % store_role)
        return store_role

    def get_auto_write_profile(self, okta_profile):
        """ Gets if should auto write aws creds to ~/.aws/credentials from config """
        auto_write_profile = self._value.get(okta_profile, 'auto-write-profile', fallback=True)
        self.logger.info("Should write profile to ~/.aws/credentials: %s" % auto_write_profile)
        return auto_write_profile

    def get_session_duration(self, okta_profile):
        """ Gets STS session duration from config as an int"""
        # AWS docs say default duration is 1 hour (3600 seconds)
        session_duration = int(self._value.get(okta_profile, 'session-duration', fallback="3600"))

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
