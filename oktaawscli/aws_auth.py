""" AWS authentication """
# pylint: disable=C0325
import os
import json
import base64
from datetime import datetime, date
import xml.etree.ElementTree as ET
from collections import namedtuple
from configparser import SafeConfigParser
import boto3
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound
import six

class AwsAuth():
    """ Methods to support AWS authentication using STS """

    def __init__(self, profile, okta_profile, account, verbose, logger, region, reset, debug=False):
        home_dir = os.path.expanduser('~')
        self.creds_dir = os.path.join(home_dir, ".aws")
        self.creds_file = os.path.join(self.creds_dir, "credentials")
        self.profile = profile
        self.account = account
        self.verbose = verbose
        self.logger = logger
        self.role = ""
        self.region = region
        self.debug = debug

        okta_info = os.path.join(home_dir, '.okta-alias-info')
        if not os.path.isfile(okta_info):
            open(okta_info, 'a').close()

        okta_config = os.path.join(home_dir, '.okta-aws')
        parser = SafeConfigParser()
        parser.read(okta_config)

        if parser.has_option(okta_profile, 'role') and not reset:
            self.role = parser.get(okta_profile, 'role')
            self.logger.debug("Setting AWS role to %s" % self.role)

    def choose_aws_role(self, assertion):
        """ Choose AWS role from SAML assertion """

        roles = self.__extract_available_roles_from(assertion)
        if self.account:
            roles = [elem for elem in roles if self.account in elem[1]]
        role_info = self.__get_role_info(roles, assertion)
        if self.role:
            predefined_role = self.__find_predefined_role_from(role_info)
            if predefined_role:
                self.logger.info("Using predefined role: %s" % self.role)
                return predefined_role
            else:
                self.logger.info("""Predefined role, %s, not found in the list
of roles assigned to you.""" % self.role)
                self.logger.info("Please choose a role.")

        if len(roles) == 1:
            print("One role found, using role: %s" % roles[0][1])
            return role_info[0]

        role_options = self.__create_options_from(role_info)
        role_choice = None
        while role_choice is None:
            try:
                for option in role_options:
                    print(option)
                role_choice = int(input('Please select the AWS role: ')) - 1
                if role_choice >= 0 and role_choice < len(role_info):
                    return role_info[role_choice]
                raise IndexError('Bad selection')
            except (SyntaxError, NameError, ValueError, IndexError):
                print("\nYou have selected an invalid role index, please try again.\n")
                role_choice = None

    def get_sts_token(self, role_arn, principal_arn, assertion, duration):
        """ Gets a token from AWS STS """

        try:
            profile = os.environ.pop('AWS_PROFILE', None)
            # Connect to the GovCloud STS endpoint if a GovCloud ARN is found.
            arn_region = principal_arn.split(':')[1]
            if arn_region == 'aws-us-gov':
                sts = boto3.client('sts', region_name='us-gov-west-1')
            else:
                sts = boto3.client('sts', region_name=self.region)
            if profile is not None:
                os.environ['AWS_PROFILE'] = profile
        except ProfileNotFound:
            self.logger.exception("Unable to handle AWS_PROFILE=%s" % os.environ['AWS_PROFILE'])

        response = sts.assume_role_with_saml(RoleArn=role_arn,
                                             PrincipalArn=principal_arn,
                                             SAMLAssertion=assertion,
                                             DurationSeconds=duration)
        credentials = response['Credentials']
        return credentials

    def check_sts_token(self, profile):
        """ Verifies that STS credentials are valid """
        # Don't check for creds if profile is blank
        if not profile:
            return False

        parser = SafeConfigParser()
        parser.read(self.creds_file)

        if not os.path.exists(self.creds_dir):
            self.logger.info(
                "AWS credentials path does not exist. Not checking.")
            return False

        elif not os.path.isfile(self.creds_file):
            self.logger.info(
                "AWS credentials file does not exist. Not checking.")
            return False

        elif not parser.has_section(profile):
            self.logger.info(
                "No existing credentials found. Requesting new credentials.")
            return False

        session = boto3.Session(profile_name=profile)
        sts = session.client('sts')
        try:
            sts.get_caller_identity()

        except (ClientError, NoCredentialsError) as ex:
            if str(ex) == 'Unable to locate credentials':
                self.logger.info(
                    "No credentials have been located. Requesting new credentials.")
                return False
            elif ex.response['Error']['Code'] == 'ExpiredToken':
                self.logger.info(
                    "Temporary credentials have expired. Requesting new credentials.")
                return False

        print("AWS credentials are valid. Nothing to do.")
        self.logger.info("STS credentials are valid. Nothing to do.")
        return True

    def write_sts_token(self, profile, access_key_id, secret_access_key, session_token, region=None):
        """ Writes STS auth information to credentials file """
        region = region or self.region
        output = 'json'
        if not os.path.exists(self.creds_dir):
            os.makedirs(self.creds_dir)
        config = SafeConfigParser()

        if os.path.isfile(self.creds_file):
            config.read(self.creds_file)

        if not config.has_section(profile):
            config.add_section(profile)

        config.set(profile, 'output', output)
        config.set(profile, 'region', region)
        config.set(profile, 'aws_access_key_id', access_key_id)
        config.set(profile, 'aws_secret_access_key', secret_access_key)
        config.set(profile, 'aws_session_token', session_token)
        config.set(profile, 'aws_security_token', session_token)

        with open(self.creds_file, 'w+') as configfile:
            config.write(configfile)
        print("Temporary credentials written to profile: %s" % profile)
        self.logger.info("Invoke using: aws --profile %s <service> <command>" % profile)

    def copy_to_default(self, profile):
        """ Reads STS auth information from credentials file """
        if not os.path.exists(self.creds_dir):
            os.makedirs(self.creds_dir)
        config = SafeConfigParser()

        if os.path.isfile(self.creds_file):
            config.read(self.creds_file)

        if not config.has_section(profile):
            config.add_section(profile)

        if config.has_option(profile, 'output'):
            config.set('default', 'output', config.get(profile, 'output'))

        if config.has_option(profile, 'region'):
            config.set('default', 'region', config.get(profile, 'region'))

        if config.has_option(profile, 'aws_access_key_id'):
            config.set('default', 'aws_access_key_id', config.get(profile, 'aws_access_key_id'))

        if config.has_option(profile, 'aws_secret_access_key'):
            config.set('default', 'aws_secret_access_key',
                       config.get(profile, 'aws_secret_access_key'))

        if config.has_option(profile, 'aws_session_token'):
            config.set('default', 'aws_session_token', config.get(profile, 'aws_session_token'))

        if config.has_option(profile, 'aws_security_token'):
            config.set('default', 'aws_security_token', config.get(profile, 'aws_security_token'))

        with open(self.creds_file, 'w+') as configfile:
            config.write(configfile)

    @staticmethod
    def __extract_available_roles_from(assertion):
        aws_attribute_role = 'https://aws.amazon.com/SAML/Attributes/Role'
        attribute_value_urn = '{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'
        roles = []
        role_tuple = namedtuple("RoleTuple", ["principal_arn", "role_arn"])
        root = ET.fromstring(base64.b64decode(assertion))
        for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
            if saml2attribute.get('Name') == aws_attribute_role:
                for saml2attributevalue in saml2attribute.iter(attribute_value_urn):
                    roles.append(role_tuple(*saml2attributevalue.text.split(',')))
        return roles

    def __get_role_info(self, roles, assertion):
        """ Gets role info from okta-info.json """
        info_file_path = os.path.expanduser('~') + "/.okta-alias-info"
        info_file = open(info_file_path, 'r')
        okta_info = info_file.read()
        if okta_info == "":
            okta_info = {}
        else:
            okta_info = json.loads(okta_info)
        info_file.close()

        role_info = []
        new_okta_info = {}
        for role in roles:
            # read the role info from ~/.okta-info.json
            role_updated = okta_info.get(role.role_arn, {})
            alias = role_updated.get('alias')

            last_updated = role_updated.get('last_updated', "0001-01-01")
            last_updated = datetime.strptime(last_updated, '%Y-%m-%d').date()
            current_date = date.today()
            alias_age = current_date - last_updated
            if alias_age.days >= 7 or alias is None:
                self.logger.info("Refreshing cached alias for role %s" % role.role_arn)
                alias = self.__get_account_alias(role.role_arn, role.principal_arn, assertion)
                last_updated = current_date
                if alias is None:
                    continue

            self.logger.info("Using cached alias for role %s" % role.role_arn)
            role_info.append(
                (role.role_arn, role.principal_arn, alias)
            )
            new_okta_info[role.role_arn] = {
                'last_updated': last_updated,
                'alias': alias
            }

        info_file = open(info_file_path, 'w')
        info_file.write(json.dumps(new_okta_info,
                                   sort_keys=True,
                                   indent=4,
                                   separators=(',', ': '),
                                   default=str
                                  )
                       )
        info_file.close()
        role_info = sorted(role_info, key=lambda role: (role[2], role[0]))
        return role_info

    def __get_account_alias(self, role_arn, principal_arn, assertion):
        """
        Gets account alias for given role
        :param role_arn: The ARN of the role.
        :param principal_arn: The ARN of the principle.
        :param assertion: The SAML assertion.
        :return: The alias of the account that this role is in. "Unknown" is returned if the role does not
        have access to the account's alias. None is returned if the role cannot be assumed.
        """
        try:
            profile = os.environ.pop('AWS_PROFILE', None)
            sts = boto3.client('sts')
            if profile is not None:
                os.environ['AWS_PROFILE'] = profile
        except ProfileNotFound:
            self.logger.exception("Unable to handle AWS_PROFILE=%s" % os.environ['AWS_PROFILE'])
        try:
            saml_resp = sts.assume_role_with_saml(
                RoleArn=role_arn,
                PrincipalArn=principal_arn,
                SAMLAssertion=assertion
            )
        except ClientError as ex:
            self.logger.warning(
                "Unable to assume role '%s', cannot get account alias",
                role_arn,
                exc_info=self.debug
            )
            return None

        iam = boto3.client(
            'iam',
            aws_access_key_id=saml_resp['Credentials']['AccessKeyId'],
            aws_secret_access_key=saml_resp['Credentials']['SecretAccessKey'],
            aws_session_token=saml_resp['Credentials']['SessionToken']
        )

        try:
            alias_resp = iam.list_account_aliases()
            return alias_resp['AccountAliases'][0]
        except ClientError as ex:
            if ex.response['Error']['Code'] == 'AccessDenied':
                self.logger.info(
                    'Role %s not authorized to perform `list_account_aliases`.',
                    role_arn,
                    exc_info=self.debug
                )
            return "unknown"

    @staticmethod
    def __create_options_from(roles):
        options = []
        for index, role in enumerate(roles):
            # role[0] is the role arn, role[2] is the account alias
            options.append("[%s]: %s : %s" % (str(index + 1).ljust(2), role[2].ljust(27), role[0]))
        return options

    def __find_predefined_role_from(self, roles):
        # role_tuple[0] is the role arn
        found_roles = (role_tuple for role_tuple in roles if role_tuple[0] == self.role)
        return next(found_roles, None)
