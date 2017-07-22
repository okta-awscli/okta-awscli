""" Wrapper script for awscli which handles Okta auth """
from collections import namedtuple
import base64
import xml.etree.ElementTree as ET
import os
from ConfigParser import RawConfigParser
from okta_auth import OktaAuth
import boto3

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

def main():
    """ Main entrypoint """
    okta = OktaAuth()
    app_name, assertion = okta.get_assertion()
    app_name = app_name.replace(" ", "")
    role = choose_aws_role(assertion)
    principal_arn, role_arn = role

    role_name = role_arn.split('/')[1]
    profile = "okta-%s-%s" % (app_name, role_name)

    token = get_sts_token(role_arn, principal_arn, assertion)
    access_key_id = token['AccessKeyId']
    secret_access_key = token['SecretAccessKey']
    session_token = token['SessionToken']
    write_sts_token(profile, access_key_id, secret_access_key, session_token)

if __name__ == "__main__":
    main()
