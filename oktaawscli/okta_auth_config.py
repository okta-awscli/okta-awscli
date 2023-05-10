""" Config helper """

from errno import ESTALE
import os
import re
import sys
from configparser import RawConfigParser
from getpass import getpass
import validators
from validators.utils import validator


from oktaawscli.util import input

def get_maybe_env_var(input):
    """ return value from environment if set. """
    if env_var(input):
        return os.environ.get(input.strip()[2:-1])
    return input

@validator
def env_var(input):
    """ validate input is can be an $-enclosed environment variable, e.g. `${ENV_VAR}` """
    _input = input.strip()
    return all([
        _input[:2] == '${', 
        _input[-1] == '}',
        re.match(r'[a-zA-Z_]+[a-zA-Z0-9_]*', _input[2:-1])
    ])

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
        config_exists = os.path.exists(config_path)
        if config_exists:
            value.read(config_path)
            print(f"You have preconfigured Okta profiles: {value.sections()}")
            print(f"This command will append new profile to the existing {config_path} config file")
            
        else:
            print(f"This command will create a new {config_path} config file")

        confirm = input('Would you like to proceed? [y/n]: ')
        if confirm == 'y':
            logger.info(f"{'Appending config to' if config_exists else 'Creating new'} {config_path} file")
            print("to specify an environment variable enter the variable name as `${ENV_VARIABLE_NAME}`")
            okta_profile = input('Enter Okta profile name: ')
            if not okta_profile:
                okta_profile = 'default'
            profile = input('Enter AWS profile name or env var: ')
            base_url = input('Enter Okta base url or env var [your main organisation Okta url]: ')
            username = input('Enter Okta username or env var: ')
            app_link = input('Enter AWS app-link or env var [optional]: ')
            duration = input('Duration in seconds or env var to request a session token for [Default=3600]: ')
            if not duration:
                duration = 3600

            value.add_section(okta_profile)
            value.set(okta_profile, 'base-url', base_url)
            value.set(okta_profile, 'profile', profile)
            value.set(okta_profile, 'username', username)
            if app_link:
                value.set(okta_profile, 'app-link', app_link)
            value.set(okta_profile, 'duration', duration)

            with open(config_path, 'w') as configfile:
                value.write(configfile)

            print(f"Configuration {config_path} successfully updated. Now you can authenticate to Okta")
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
        
        app_link = get_maybe_env_var(app_link)
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

    def totp_token_for(self, okta_profile):
        """ Reads the totp token from the env var """
        if self._value.has_option(okta_profile, 'totp_token'):
            token_var = self._value.get(okta_profile, 'totp_token')
            token = get_maybe_env_var(token_var)
        else:
            token = input('Enter token: ')
        return token

    def username_for(self, okta_profile):
        """ Gets username from config """
        if self._value.has_option(okta_profile, 'username'):
            username = self._value.get(okta_profile, 'username')
            username = get_maybe_env_var(username)
            self.logger.info("Authenticating as: %s" % username)
        else:
            username = input('Enter username: ')
        return username

    def password_for(self, okta_profile):
        """ Gets password from config """
        if self._value.has_option(okta_profile, 'password'):
            password = self._value.get(okta_profile, 'password')
            password = get_maybe_env_var(password)
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
            duration = get_maybe_env_var(duration)
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

    @staticmethod
    def get_okta_profiles():
        value = RawConfigParser()
        config_path = os.path.expanduser('~') + '/.okta-aws'
        value.read(config_path)
        return value.sections()
