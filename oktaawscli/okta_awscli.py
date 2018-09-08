""" Wrapper script for awscli which handles Okta auth """
# pylint: disable=C0325,R0913,R0914
import os
from subprocess import call
import logging
import sys
import click
from oktaawscli.version import __version__
from oktaawscli.okta_auth import OktaAuth
from oktaawscli.okta_auth_config import OktaAuthConfig
from oktaawscli.aws_auth import AwsAuth

def get_credentials(okta_profile, profile, account, write_default, verbose, logger,
                    totp_token, cache, export, reset, force):
    """ Gets credentials from Okta """
    okta_auth_config = OktaAuthConfig(logger, reset)

    region = okta_auth_config.region_for(okta_profile)
    aws_auth = AwsAuth(profile, okta_profile, account, verbose, logger, region, reset)

    check_creds = okta_auth_config.get_check_valid_creds(okta_profile)
    if not force and check_creds and aws_auth.check_sts_token(profile):
        if write_default:
            aws_auth.copy_to_default(profile)
            sys.stderr.write("\nCopying account token to default\n")
        exit(0)

    okta = OktaAuth(okta_profile, verbose, logger,
                    totp_token, okta_auth_config)

    _, assertion = okta.get_assertion()
    role = aws_auth.choose_aws_role(assertion)
    role_arn, principal_arn, alias = role

    auto_write = okta_auth_config.get_auto_write_profile(okta_profile)
    if auto_write == "True" and profile is None:
        profile_name = "default" if alias == "unknown" else alias
    else:
        profile_name = profile

    store_role = okta_auth_config.get_store_role(okta_profile)
    if store_role == "True":
        okta_auth_config.save_chosen_role_for_profile(okta_profile, role_arn)

    duration = okta_auth_config.get_session_duration(okta_profile)
    sts_token = aws_auth.get_sts_token(role_arn, principal_arn, assertion, duration)
    access_key_id = sts_token['AccessKeyId']
    secret_access_key = sts_token['SecretAccessKey']
    session_token = sts_token['SessionToken']
    sys.stderr.write("Credentials valid for %s hours \n" % round(duration/3600, 1))
    if (profile_name is None or export) and not write_default:
        logger.info("Either profile name not given or export flag set, will output to console.")
        exports = console_output(access_key_id, secret_access_key,
                                 session_token, verbose)
        if cache:
            cache = open("%s/.okta-credentials.cache" %
                         (os.path.expanduser('~'),), 'w')
            cache.write(exports)
            cache.close()
        exit(0)
    else:
        logger.info("Export flag not set, will write credentials to ~/.aws/credentials.")
        aws_auth.write_sts_token(profile_name, access_key_id,
                                 secret_access_key, session_token)
        if write_default:
            aws_auth.write_sts_token('default', access_key_id,
                                     secret_access_key, session_token)
        else:
            usage_msg = "".join([
                "\nTo start using these temporary credentials, run:\n",
                "\n export AWS_PROFILE=%s\n" % profile_name
            ])
            sys.stderr.write(usage_msg)
        exit(0)

def console_output(access_key_id, secret_access_key, session_token, verbose):
    """ Outputs STS credentials to console """
    if verbose:
        sys.stderr.write("Use these to set your environment variables:")
    exports = "\n".join([
        "export AWS_ACCESS_KEY_ID=%s" % access_key_id,
        "export AWS_SECRET_ACCESS_KEY=%s" % secret_access_key,
        "export AWS_SESSION_TOKEN=%s" % session_token,
        "export AWS_SECURITY_TOKEN=%s" % session_token
    ])
    print(exports)

    return exports

# pylint: disable=R0913
@click.command()
@click.option('-v', '--verbose', is_flag=True, help='Enables verbose mode')
@click.option('-w', '--write-default', is_flag=True, help='Writes to both default and account')
@click.option('-V', '--version', is_flag=True,
              help='Outputs version number and exits')
@click.option('-d', '--debug', is_flag=True, help='Enables debug mode')
@click.option('-f', '--force', is_flag=True, help='Forces new STS credentials. \
Skips STS credentials validation.')
@click.option('-r', '--reset', is_flag=True, help='Resets default values in ~/.okta-aws')
@click.option('-e', '--export', is_flag=True, help='Outputs credentials to console instead \
of writing to ~/.aws/credentials')
@click.option('--okta-profile', help="Name of the profile to use in .okta-aws. \
If none is provided, then the default profile will be used.\n")
@click.option('--profile', help="Name of the profile to store temporary \
credentials in ~/.aws/credentials. If profile doesn't exist, it will be \
created. If omitted, credentials will output to console.\n")
@click.option('-c', '--cache', is_flag=True, help='Cache the default profile credentials \
to ~/.okta-credentials.cache\n')
@click.option('-t', '--token', help='TOTP token from your authenticator app')
@click.option('-a', '--account', help='Target account to authenticate to. \
Also writes AWS credentials to default profile ')
@click.argument('awscli_args', nargs=-1, type=click.UNPROCESSED)
def main(okta_profile, profile, verbose, version, write_default,
         debug, force, export, cache, awscli_args, token, reset, account):
    """ Authenticate to awscli using Okta """
    if version:
        print(__version__)
        exit(0)
    # Set up logging
    logger = logging.getLogger('okta-awscli')
    logger.setLevel(logging.DEBUG)
    handler = logging.StreamHandler()
    handler.setLevel(logging.WARN)
    formatter = logging.Formatter('%(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    if verbose:
        handler.setLevel(logging.INFO)
    if debug:
        handler.setLevel(logging.DEBUG)
    logger.addHandler(handler)

    if not okta_profile:
        okta_profile = "default"
    if account:
        profile = account
        okta_profile = account
    get_credentials(
        okta_profile, profile, account, write_default, verbose, logger,
        token, cache, export, reset, force
    )

    if awscli_args:
        cmdline = ['aws', '--profile', profile] + list(awscli_args)
        logger.info('Invoking: %s', ' '.join(cmdline))
        call(cmdline)

if __name__ == "__main__":
    # pylint: disable=E1120
    main()
    # pylint: enable=E1120
