""" Wrapper script for awscli which handles Okta auth """
from subprocess import call
from okta_auth import OktaAuth
from aws_auth import AwsAuth
import click

def get_credentials(aws_auth, okta_profile, profile, verbose):
    """ Gets credentials from Okta """
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

@click.command()
@click.option('-v', '--verbose', is_flag=True, help='Enables verbose mode')
@click.option('--okta_profile', help="Name of the profile to use in .okta-aws. \
If none is provided, then the default profile will be used.")
@click.option('--profile', required=True, help="Name of the profile to store temporary \
credentials in ~/.aws/credentials. If profile doesn't exist, it will be created.")
@click.argument('awscli_args', nargs=-1, type=click.UNPROCESSED)
def main(okta_profile, profile, verbose, awscli_args):
    """ Main entrypoint """
    if not okta_profile:
        okta_profile = "default"

    aws_auth = AwsAuth(profile, verbose)
    if not aws_auth.check_sts_token(profile):
        get_credentials(aws_auth, okta_profile, profile, verbose)

    cmdline = ['aws', '--profile', profile] + list(awscli_args)

    if verbose:
        click.echo('Invoking: %s' % ' '.join(cmdline))

    call(cmdline)

if __name__ == "__main__":
    #pylint: disable=E1120
    main()
    #pylint: enable=E1120
