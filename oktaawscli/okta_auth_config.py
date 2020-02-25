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
    def __init__(self, logger):
        self.logger = logger
        self.config_path = os.path.expanduser('~') + '/.okta-aws'
        self._value = RawConfigParser()
        self._value.read(self.config_path)

    def base_url_for(self, okta_profile):
        """ Gets base URL from config """
        if self._value.has_option(okta_profile, 'base-url'):
            base_url = self._value.get(okta_profile, 'base-url')
            self.logger.info("Authenticating to: %s" % base_url)
        elif self._value.has_option('default', 'base-url'):
            base_url = self._value.get('default', 'base-url')
            self.logger.info(
                "Using base-url from default profile %s" % base_url
            )
        else:
            self.logger.error(
                "No profile found. Please define a default profile, or specify a named profile using `--okta-profile`"
            )
            exit(1)
        return base_url

    def app_link_for(self, okta_profile):
        """ Gets app_link from config """
        app_link = None
        if self._value.has_option(okta_profile, 'app-link'):
            app_link = self._value.get(okta_profile, 'app-link')
        elif self._value.has_option('default', 'app-link'):
            app_link = self._value.get('default', 'app-link')
        self.logger.info("App Link set as: %s" % app_link)
        return app_link

    def username_for(self, okta_profile):
        """ Gets username from config """
        if self._value.has_option(okta_profile, 'username'):
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
        if self._value.has_option(okta_profile, 'factor'):
            factor = self._value.get(okta_profile, 'factor')
            self.logger.debug("Setting MFA factor to %s" % factor)
            return factor
        return None

    def duration_for(self, okta_profile):
        """ Gets requested duration from config, ignore it on failure """
        if self._value.has_option(okta_profile, 'duration'):
            duration = self._value.get(okta_profile, 'duration')
            self.logger.debug(
                "Requesting a duration of %s seconds" % duration
            )
            try:
                return int(duration)
            except ValueError as e:
                self.logger.warn(
                    "Duration could not be converted to a number,"
                    " ignoring."
                )
        return None

    def save_chosen_role_for_profile(self, okta_profile, role_arn):
        """ Gets role from config """
        if not self._value.has_section(okta_profile):
            self._value.add_section(okta_profile)

        base_url = self.base_url_for(okta_profile)
        self._value.set(okta_profile, 'base-url', base_url)
        self._value.set(okta_profile, 'role', role_arn)

        with open(self.config_path, 'w+') as configfile:
            self._value.write(configfile)

    def save_chosen_app_link_for_profile(self, okta_profile, app_link):
        """ Gets role from config """
        if not self._value.has_section(okta_profile):
            self._value.add_section(okta_profile)

        base_url = self.base_url_for(okta_profile)
        self._value.set(okta_profile, 'base-url', base_url)
        self._value.set(okta_profile, 'app-link', app_link)

        with open(self.config_path, 'w+') as configfile:
            self._value.write(configfile)
