# okta-awscli - Retrieve AWS credentials from Okta

Master branch: [![Build Status - master](https://travis-ci.org/jmhale/okta-awscli.svg?branch=master)](https://travis-ci.org/jmhale/okta-awscli)

Develop branch: [![Build Status - develop](https://travis-ci.org/jmhale/okta-awscli.svg?branch=develop)](https://travis-ci.org/jmhale/okta-awscli)

Authenticates a user against Okta and then uses the resulting SAML assertion to retrieve temporary STS credentials from AWS.

This project is largely inspired by https://github.com/nimbusscale/okta_aws_login, but instead uses a purely API-driven approach, instead of parsing HTML during the authentication phase.

## Installation

See [AstroTools: New Engineer Setup - Amplify Okta AWS CLI](https://docs.google.com/document/d/13UpNzew2sXssfVZSMaOdsx2hMXLNTjgHba8HieeFlqg/edit#heading=h.lm3ca6e4w2w5)

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
- Multiple Okta profiles are supported, but if none are specified, then `default` will be used.


### Examples

`okta-awscli --profile cfer-dev`

This command will simply output STS credentials to `cfer-dev` in your credentials file.


`okta-awscli --profile my-aws-account iam list-users`

If no awscli commands are provided, then okta-awscli will simply output STS credentials to your credentials file, or console, depending on how `--profile` is set.

Optional flags:
- `--profile` Sets your temporary credentials to a profile in `.aws/credentials`. If omitted, credentials will output to console.
- `--export` Outputs credentials to console instead of writing to ~/.aws/credentials.
- `--reset` Resets default values in ~/.okta-aws for the okta-profile being used.
- `--force` Ignores result of STS credentials validation and gets new credentials from AWS. Used in conjunction with `--profile`.
- `--verbose` More verbose output.
- `--debug` Very verbose output. Useful for debugging.
- `--cache` Cache the acquired credentials to ~/.okta-credentials.cache (only if --profile is unspecified)
- `--okta-profile` Use a Okta profile, other than `default` in `.okta-aws`. Useful for multiple Okta tenants.
- `--token` or `-t` Pass in the TOTP token from your authenticator
