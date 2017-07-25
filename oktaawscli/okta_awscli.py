""" Wrapper script for awscli which handles Okta auth """
#pylint: disable=C0325
from subprocess import call
from oktaawscli.okta_auth import OktaAuth
from oktaawscli.aws_auth import AwsAuth
import click

def get_credentials(aws_auth, okta_profile, profile, verbose):
    """ Gets credentials from Okta """
    okta = OktaAuth(okta_profile, verbose)
    app_name, assertion = okta.get_assertion()
    app_name = app_name.replace(" ", "")
    role = aws_auth.choose_aws_role(assertion)
    principal_arn, role_arn = role

    token = aws_auth.get_sts_token(role_arn, principal_arn, assertion)
    access_key_id = token['AccessKeyId']
    secret_access_key = token['SecretAccessKey']
    session_token = token['SessionToken']
    if not profile:
        console_output(access_key_id, secret_access_key, session_token, verbose)
        exit(0)
    else:
        aws_auth.write_sts_token(profile, access_key_id, secret_access_key, session_token)

def console_output(access_key_id, secret_access_key, session_token, verbose):
    """ Outputs STS credentials to console """
    if verbose:
        print("Use these to set your environment variables:")
    print("export AWS_ACCESS_KEY_ID=%s" % access_key_id)
    print("export AWS_SECRET_ACCESS_KEY=%s" % secret_access_key)
    print("export AWS_SESSION_TOKEN=%s" % session_token)

#pylint: disable=R0913
@click.command()
@click.option('-v', '--verbose', is_flag=True, help='Enables verbose mode')
@click.option('-f', '--force', is_flag=True, help='Forces new STS credentials. \
Skips STS credentials validation.')
@click.option('--okta_profile', help="Name of the profile to use in .okta-aws. \
If none is provided, then the default profile will be used.")
@click.option('--profile', help="Name of the profile to store temporary \
credentials in ~/.aws/credentials. If profile doesn't exist, it will be created. If omitted, credentials \
will output to console.")
@click.argument('awscli_args', nargs=-1, type=click.UNPROCESSED)
def main(okta_profile, profile, verbose, force, awscli_args):
    """ Authenticate to awscli using Okta """
    if not okta_profile:
        okta_profile = "default"
    aws_auth = AwsAuth(profile, verbose)
    if not aws_auth.check_sts_token(profile) or force:
        if verbose and force and profile:
            click.echo("Force option selected, getting new credentials anyway.")
        elif verbose and force:
            click.echo("Force option selected, but no profile provided. Option has no effect.")
        get_credentials(aws_auth, okta_profile, profile, verbose)

    if awscli_args:
        cmdline = ['aws', '--profile', profile] + list(awscli_args)
        if verbose:
            click.echo('Invoking: %s' % ' '.join(cmdline))
        call(cmdline)

if __name__ == "__main__":
    #pylint: disable=E1120
    main()
    #pylint: enable=E1120
