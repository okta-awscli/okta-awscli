""" Wrapper script for awscli which handles Okta auth """
from collections import namedtuple
import base64
import xml.etree.ElementTree as ET
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
    print credentials


def main():
    """ Main entrypoint """
    okta = OktaAuth()
    assertion = okta.get_assertion()
    role = choose_aws_role(assertion)
    principal_arn, role_arn = role
    get_sts_token(role_arn, principal_arn, assertion)

if __name__ == "__main__":
    main()
