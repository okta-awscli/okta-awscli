# okta-awscli - Retrieve AWS credentials from Okta

Master branch: [![Build Status - master](https://travis-ci.org/jmhale/okta-awscli.svg?branch=master)](https://travis-ci.org/jmhale/okta-awscli)

Develop branch: [![Build Status - develop](https://travis-ci.org/jmhale/okta-awscli.svg?branch=develop)](https://travis-ci.org/jmhale/okta-awscli)

Authenticates a user against Okta and then uses the resulting SAML assertion to retrieve temporary STS credentials from AWS.

This project is largely inspired by https://github.com/nimbusscale/okta_aws_login, but instead uses a purely API-driven approach, instead of parsing HTML during the authentication phase.

Parsing the HTML is still required to get the SAML assertion, after authentication is complete. However, since we only need to look for the SAML assertion in a single, predictable tag, `<input name="SAMLResponse"...`, the results are a lot more stable across any changes that Okta may make to their interface.


## Installation

- `pip install okta-awscli`
- Configure okta-awscli via the `~/.okta-aws` file with the following parameters:

```
[default]
base-url = <your_okta_org>.okta.com

## These parameters are optional flags to change the default behavior of okta-awscli
auto-write-profile = True
# Set the above to "True" if you want to automatically write creds to ~/.aws/credentials. Defaults to False.
check-valid-creds = False
# Set the above to "False" if you want new credentials everytime you run okta-awscli. Defaults to True
store-role = False
# Set the above to "False" if you want to be prompted for a role everytime you run okta-awscli rather than having the role selected for you. Defaults to True.

## The remaining parameters are optional.
## You will be prompted for them, if they're not included here.
username = <your_okta_username>
factor = <your_preferred_mfa_factor> # Current choices are: GOOGLE or OKTA
role = <your_preferred_okta_role> # AWS role name (match one of the options prompted for by "Please select the AWS role" when this parameter is not specified
app = <your_prefered_okta_app> # ex. `Amazon Web Services` to automatically select Amazon Web Services

```

## Supported Features

- Tenant wide MFA support
- Okta Verify [Play Store](https://play.google.com/store/apps/details?id=com.okta.android.auth) | [App Store](https://itunes.apple.com/us/app/okta-verify/id490179405)
- Okta Verify Push Support
- Google Authenticator [Play Store](https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2) | [App Store](https://itunes.apple.com/us/app/google-authenticator/id388497605)


## Unsupported Features

- Per application MFA support


## Usage

`okta-awscli --profile <aws_profile> <awscli action> <awscli arguments>`
- Follow the prompts to enter MFA information (if required) and choose your AWS app and IAM role.
- The default Okta profile will not store your chosen IAM role, but other profiles will.
- Multiple Okta profiles are supported, but if none are specified, then `default` will be used.


### Examples

`okta-awscli --profile cfer-dev`

This command will simply output STS credentials to `cfer-dev` in your credentials file.


`okta-awscli --profile my-aws-account iam list-users`

If no awscli commands are provided, then okta-awscli will simply output STS credentials to your credentials file, or console, depending on how `--profile` is set.

Optional flags:
- `--profile` Sets your temporary credentials to a profile in `.aws/credentials`. If omitted, credentials will output to console.
- `--export` Outputs credentials to console instead of writing to ~/.aws/credentials.
- `--reset` Resets default values in ~/.okta-aws.
- `--verbose` More verbose output.
- `--debug` Very verbose output. Useful for debugging.
- `--cache` Cache the acquired credentials to ~/.okta-credentials.cache (only if --profile is unspecified)
- `--okta-profile` Use a Okta profile, other than `default` in `.okta-aws`. Useful for multiple Okta tenants.
- `--token` or `-t` Pass in the TOTP token from your authenticator
