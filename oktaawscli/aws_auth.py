""" AWS authentication """
# pylint: disable=C0325
import os
import sys
import base64
import xml.etree.ElementTree as ET
from collections import namedtuple
from configparser import RawConfigParser
from enum import Enum
import boto3
from botocore.exceptions import ClientError


class AwsPartition(Enum):
    AWS = 1 
    AWS_US_GOV = 2


class AwsAuth():
    """ Methods to support AWS authentication using STS """

    def __init__(self, profile, okta_profile, lookup, verbose, logger):
        home_dir = os.path.expanduser('~')
        self.creds_dir = home_dir + "/.aws"
        self.creds_file = self.creds_dir + "/credentials"
        self.lookup = lookup
        self.profile = profile
        self.verbose = verbose
        self.logger = logger
        self.role = ""
        self.aws_partition = AwsPartition.AWS

        okta_config = home_dir + '/.okta-aws'
        parser = RawConfigParser()
        parser.read(okta_config)

        if parser.has_option(okta_profile, 'role'):
            self.role = parser.get(okta_profile, 'role')
            self.logger.debug("Setting AWS role to %s" % self.role)
            self.aws_partition = self.__find_aws_partition_from_role_arn(self.role)
            self.logger.debug("Setting AWS partition to %s" % self.aws_partition)

        if parser.has_option(okta_profile, 'profile') and not profile:
            self.profile = parser.get(okta_profile, 'profile')
            self.logger.debug("Setting AWS profile to %s" % self.profile)


    def choose_aws_role(self, assertion, refresh_role):
        """ Choose AWS role from SAML assertion """

        roles = self.__extract_available_roles_from(assertion)
        if self.role:
            predefined_role = self.__find_predefined_role_from(roles)
            if predefined_role and not refresh_role:
                self.logger.info("Using predefined role: %s" % self.role)
                return predefined_role
            elif refresh_role:
                self.logger.info("""Refreshing role""")
            else:
                self.logger.info("""Predefined role, %s, not found in the list
of roles assigned to you.""" % self.role)

        self.logger.info("Please choose a role.")
        role_options = self.__create_options_from(roles, assertion, self.lookup)
        for option in role_options:
            print(option)

        role_choice = int(input('Please select the AWS role: ')) - 1
        return roles[role_choice]

    @staticmethod
    def get_sts_token(role_arn, principal_arn, assertion, duration=None, logger=None):
        """ Gets a token from AWS STS """

        # Connect to the GovCloud STS endpoint if a GovCloud ARN is found.
        aws_partition = AwsAuth.__find_aws_partition_from_role_arn(principal_arn)
        logger.debug("Getting STS token against ARN partition: %s" % aws_partition)
        if aws_partition == AwsPartition.AWS_US_GOV:
            sts = boto3.client('sts', region_name='us-gov-west-1')
        else:
            sts = boto3.client('sts')

        try:
            response = sts.assume_role_with_saml(RoleArn=role_arn,
                                                 PrincipalArn=principal_arn,
                                                 SAMLAssertion=assertion,
                                                 DurationSeconds=duration or 3600)
        except ClientError as ex:
            if logger:
                logger.error(
                    "Could not retrieve credentials: %s" %
                    ex.response['Error']['Message']
                )
                sys.exit(-1)
            else:
                raise

        credentials = response['Credentials']
        return credentials

    def check_sts_token(self, profile):
        """ Verifies that STS credentials are valid """
        # Don't check for creds if profile is blank
        if not self.profile:
            return False

        parser = RawConfigParser()
        parser.read(self.creds_file)

        if not os.path.exists(self.creds_dir):
            self.logger.info("AWS credentials path does not exist. Not checking.")
            return False

        elif not os.path.isfile(self.creds_file):
            self.logger.info("AWS credentials file does not exist. Not checking.")
            return False

        elif not parser.has_section(self.profile):
            self.logger.info("No existing credentials found. Requesting new credentials.")
            return False

        self.logger.debug("Checking STS token against ARN partition: %s" % self.aws_partition)
        if self.aws_partition == AwsPartition.AWS_US_GOV:
            session = boto3.Session(profile_name=profile, region_name='us-gov-west-1')
        else:
            session = boto3.Session(profile_name=profile)

        sts = session.client('sts')
        try:
            sts.get_caller_identity()

        except ClientError as ex:
            if ex.response['Error']['Code'] == 'ExpiredToken':
                self.logger.info("Temporary credentials have expired. Requesting new credentials.")
            elif ex.response['Error']['Code'] == 'InvalidClientTokenId':
                self.logger.info("Credential is invalid. Requesting new credentials.")
            else:
                # See https://docs.aws.amazon.com/STS/latest/APIReference/CommonErrors.html
                self.logger.info("An unhandled error occurred. Requesting new credentials.")

            return False

        self.logger.info("STS credentials are valid. Nothing to do.")
        return True

    def write_sts_token(self, access_key_id, secret_access_key, session_token):
        """ Writes STS auth information to credentials file """
        if not os.path.exists(self.creds_dir):
            os.makedirs(self.creds_dir)
        config = RawConfigParser()

        if os.path.isfile(self.creds_file):
            config.read(self.creds_file)

        if not config.has_section(self.profile):
            config.add_section(self.profile)

        config.set(self.profile, 'aws_access_key_id', access_key_id)
        config.set(self.profile, 'aws_secret_access_key', secret_access_key)
        config.set(self.profile, 'aws_session_token', session_token)

        with open(self.creds_file, 'w+') as configfile:
            config.write(configfile)
        self.logger.info("Temporary credentials written to profile: %s" % self.profile)
        self.logger.info("Invoke using: aws --profile %s <service> <command>" % self.profile)

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
                    result_set = saml2attributevalue.text.split(',')
                    if result_set[0].split(':')[5].startswith('role/'):
                        roles.append(role_tuple(*reversed(result_set)))
                    else:
                        roles.append(role_tuple(*result_set))
        return roles

    def __create_options_from(self, roles, assertion, lookup=False):
        options = []
        for index, role in enumerate(roles):
            if lookup:
                self.logger.debug("Performing AWS account alias lookup")
                creds = AwsAuth.get_sts_token(role.role_arn, role.principal_arn, assertion, duration=900, logger=self.logger)
                access_key_id = creds['AccessKeyId']
                secret_access_key = creds['SecretAccessKey']
                session_token = creds['SessionToken']
                arn_region = role.principal_arn.split(':')[1]
                iam_region = 'us-gov-west-1' if arn_region == 'aws-us-gov' else 'us-east-1'

                client = boto3.client('iam',
                                      region_name = iam_region,
                                      aws_access_key_id = access_key_id,
                                      aws_secret_access_key = secret_access_key,
                                      aws_session_token = session_token)
                try:
                    alias = client.list_account_aliases()['AccountAliases'][0]
                    rolename = role.role_arn.split(':')[5]
                    option = '{i}: {accname} - {rolename}'.format(i=index+1,
                                                                  accname = alias,
                                                                  rolename = rolename)
                except Exception as ex:
                    self.logger.warning("Unable to perform alias lookup: %s" % ex)
                    option = '{i}: {rolearn}'.format(i=index+1,
                                                     rolearn = role.role_arn)
                    pass
                options.append(option)
            else:
                options.append("%d: %s" % (index + 1, role.role_arn))
        return options

    @staticmethod
    def __find_aws_partition_from_role_arn(role_arn):
        arn_aws_partition = role_arn.split(':')[1]
        if arn_aws_partition == 'aws-us-gov':
            return AwsPartition.AWS_US_GOV
        else:
            return AwsPartition.AWS

    def __find_predefined_role_from(self, roles):
        found_roles = filter(lambda role_tuple: role_tuple.role_arn == self.role, roles)
        return next(iter(found_roles), None)
