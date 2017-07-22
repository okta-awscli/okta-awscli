""" Wrapper script for awscli which handles Okta auth """
from collections import namedtuple
import base64
import xml.etree.ElementTree as ET
import os
from ConfigParser import RawConfigParser
from okta_auth import OktaAuth
import boto3
from botocore.exceptions import ClientError
import click

def choose_aws_role(assertion):
    """ Choose AWS role from SAML assertion """
    aws_attribute_role = 'https://aws.amazon.com/SAML/Attributes/Role'
    attribute_value_urn = '{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'
    roles = []
    role_tuple = namedtuple("RoleTuple", ["principal_arn", "role_arn"])
    root = ET.fromstring(base64.b64decode(assertion))
    for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
        if saml2attribute.get('Name') == aws_attribute_role:
            for saml2attributevalue in saml2attribute.iter(attribute_value_urn):
                roles.append(role_tuple(*saml2attributevalue.text.split(',')))

    for index, role in enumerate(roles):
        role_name = role.role_arn.split('/')[1]
        print "%d: %s" % (index+1, role_name)
    role_choice = input('Please select the AWS role: ')-1
    return roles[role_choice]

def get_sts_token(role_arn, principal_arn, assertion):
    """ Gets a token from AWS STS """
    sts = boto3.client('sts')
    response = sts.assume_role_with_saml(RoleArn=role_arn,
                                         PrincipalArn=principal_arn,
                                         SAMLAssertion=assertion)
    credentials = response['Credentials']
    return credentials

def check_sts_token(profile):
    """ Verifies that STS credentials are valid """
    session = boto3.Session(profile_name=profile)
    sts = session.client('sts')
    try:
        sts.get_caller_identity()

    except ClientError as ex:
        if ex.response['Error']['Code'] == 'ExpiredToken':
            print "Temporary credentials have expired. Renewing..."
            return False

    print "STS credentials are valid. Nothing to do."
    return True

def write_sts_token(profile, access_key_id, secret_access_key, session_token):
    """ Writes STS auth information to credentials file """

    home_dir = os.path.expanduser('~')
    creds_dir = home_dir + "/.aws"
    creds_file = creds_dir + "/credentials"
    print creds_file
    region = 'us-east-1'
    output = 'json'
    if not os.path.exists(creds_dir):
        os.makedirs(creds_dir)
    config = RawConfigParser()

    if os.path.isfile(creds_file):
        config.read(creds_file)

    if not config.has_section(profile):
        config.add_section(profile)

    config.set(profile, 'output', output)
    config.set(profile, 'region', region)
    config.set(profile, 'aws_access_key_id', access_key_id)
    config.set(profile, 'aws_secret_access_key', secret_access_key)
    config.set(profile, 'aws_session_token', session_token)

    with open(creds_file, 'w+') as configfile:
        config.write(configfile)
    print "Temporary credentials written to profile: %s" % profile
    print "Invoke using: aws --profile %s <service> <command>" % profile

@click.command()
@click.option('--okta_profile', help="Name of the profile to use in .okta-aws. \
If none is provided, then the default profile will be used.")
@click.option('--profile', help="Name of the profile to store credentials. \
If none is provided, then a name comprised of the Okta app and assumed role will be used.")
def main(okta_profile, profile):
    """ Main entrypoint """
    if check_sts_token(profile):
        exit(0)
    if not okta_profile:
        okta_profile = "default"
    okta = OktaAuth(okta_profile)
    app_name, assertion = okta.get_assertion()
    app_name = app_name.replace(" ", "")
    role = choose_aws_role(assertion)
    principal_arn, role_arn = role

    role_name = role_arn.split('/')[1]
    if not profile:
        profile = "okta-%s-%s" % (app_name, role_name)

    token = get_sts_token(role_arn, principal_arn, assertion)
    access_key_id = token['AccessKeyId']
    secret_access_key = token['SecretAccessKey']
    session_token = token['SessionToken']
    write_sts_token(profile, access_key_id, secret_access_key, session_token)

if __name__ == "__main__":
    #pylint: disable=E1120
    main()
    #pylint: enable=E1120
