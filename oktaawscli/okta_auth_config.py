""" Config helper """

from errno import ESTALE
import os
import sys
from configparser import RawConfigParser
from getpass import getpass
import validators


from oktaawscli.util import input

class OktaAuthConfig():
    """ Config helper class """
    def __init__(self, logger):
        self.logger = logger
        self.config_path = os.path.expanduser('~') + '/.okta-aws'
        self._value = RawConfigParser()
        self._value.read(self.config_path)
    
    @staticmethod
    def configure(logger):
        value = RawConfigParser()
        config_path = os.path.expanduser('~') + '/.okta-aws'
        if os.path.exists(config_path):
            value.read(config_path)
            print(f"You have preconfigured Okta profiles: {value.sections()}")
            print(f"This command will append new profile to the existing {config_path} config file")
            confirm = input('Would you like to proceed? [y/n]: ')
            append = True
        else:
            print(f"This command will create a new {config_path} config file")
            confirm = input('Would you like to proceed? [y/n]: ')

        if confirm == 'y':
            logger.info(f"Creating new {config_path} file")
            okta_profile = input('Enter Okta profile name: ')
            if not okta_profile:
                okta_profile = 'default'
            profile = input('Enter AWS profile name: ')
            base_url = input('Enter Okta base url [your main organisation Okta url]: ')
            username = input('Enter Okta username: ')
            app_link = input('Enter AWS app-link [optional]: ')
            duration = input('Duration in seconds to request a session token for [Default=3600]: ')
            if not duration:
                duration = 3600

            value.add_section(okta_profile)
            value.set(okta_profile, 'base-url', base_url)
            value.set(okta_profile, 'profile', profile)
            value.set(okta_profile, 'username', username)
            if app_link:
                value.set(okta_profile, 'app-link', app_link)
            value.set(okta_profile, 'duration', duration)

            if append:
                with open(config_path, 'a') as configfile:
                    value.write(configfile)
            else:
                with open(config_path, 'w+') as configfile:
                    value.write(configfile)
            print(f"File {config_path} successfully created. Now you can authenticate to Okta")
            print(f"Execute 'okta-awscli -o {okta_profile} -p {profile} sts get-caller-identity' to authenticate and retrieve credentials")
            sys.exit(0)
        else:
            sys.exit(0)

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
            sys.exit(1)
        return base_url

    def app_link_for(self, okta_profile):
        """ Gets app_link from config """
        app_link = None
        if self._value.has_option(okta_profile, 'app-link'):
            app_link = self._value.get(okta_profile, 'app-link')
        elif self._value.has_option('default', 'app-link'):
            app_link = self._value.get('default', 'app-link')

        if app_link:
            try:
                if not validators.url(app_link):
                    self.logger.error("The app-link provided: %s is an invalid url" % app_link)
                    sys.exit(-1)
            except TypeError as ex:
                self.logger.error("Malformed string in app link URL. Ensure there are no invalid characters.")
            self.logger.info("App Link set as: %s" % app_link)
            return app_link
        else:
            self.logger.error("The app-link is missing. Will try to retrieve it from Okta")
            return None

        

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
            except ValueError:
                self.logger.warn(
                    "Duration could not be converted to a number,"
                    " ignoring."
                )
        return None

    def write_role_to_profile(self, okta_profile, role_arn):
        """ Saves role to profile in config """
        if not self._value.has_section(okta_profile):
            self._value.add_section(okta_profile)

        base_url = self.base_url_for(okta_profile)
        self._value.set(okta_profile, 'base-url', base_url)
        self._value.set(okta_profile, 'role', role_arn)

        with open(self.config_path, 'w+') as configfile:
            self._value.write(configfile)

    def write_applink_to_profile(self, okta_profile, app_link):
        """ Saves app link to profile in config """
        if not self._value.has_section(okta_profile):
            self._value.add_section(okta_profile)

        base_url = self.base_url_for(okta_profile)
        self._value.set(okta_profile, 'base-url', base_url)
        self._value.set(okta_profile, 'app-link', app_link)

        with open(self.config_path, 'w+') as configfile:
            self._value.write(configfile)
