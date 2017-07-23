""" Wrapper script for awscli which handles Okta auth """
from okta_auth import OktaAuth
from aws_auth import AwsAuth
import click

@click.command()
@click.option('-v', '--verbose', is_flag=True, help='Enables verbose mode')
@click.option('--okta_profile', help="Name of the profile to use in .okta-aws. \
If none is provided, then the default profile will be used.")
@click.option('--profile', help="Name of the profile to store credentials. \
If none is provided, then a name comprised of the Okta app and assumed role will be used.")
def main(okta_profile, profile, verbose=False):
    """ Main entrypoint """
    aws_auth = AwsAuth(profile, verbose)
    if aws_auth.check_sts_token(profile):
        exit(0)
    if not okta_profile:
        okta_profile = "default"
    okta = OktaAuth(okta_profile, verbose)
    app_name, assertion = okta.get_assertion()
    app_name = app_name.replace(" ", "")
    role = aws_auth.choose_aws_role(assertion)
    principal_arn, role_arn = role

    role_name = role_arn.split('/')[1]
    if not profile:
        profile = "okta-%s-%s" % (app_name, role_name)

    token = aws_auth.get_sts_token(role_arn, principal_arn, assertion)
    access_key_id = token['AccessKeyId']
    secret_access_key = token['SecretAccessKey']
    session_token = token['SessionToken']
    aws_auth.write_sts_token(profile, access_key_id, secret_access_key, session_token)

if __name__ == "__main__":
    #pylint: disable=E1120
    main()
    #pylint: enable=E1120
