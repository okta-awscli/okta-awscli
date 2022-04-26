# okta-awscli - Retrieve AWS credentials from Okta

Main branch: [![Build Status - main](https://travis-ci.org/jmhale/okta-awscli.svg?branch=main)](https://travis-ci.org/jmhale/okta-awscli)

Develop branch: [![Build Status - develop](https://travis-ci.org/jmhale/okta-awscli.svg?branch=develop)](https://travis-ci.org/jmhale/okta-awscli)

Authenticates a user against Okta and then uses the resulting SAML assertion to retrieve temporary STS credentials from AWS.

This project is largely inspired by https://github.com/nimbusscale/okta_aws_login, but instead uses a purely API-driven approach, instead of parsing HTML during the authentication phase.

Parsing the HTML is still required to get the SAML assertion, after authentication is complete. However, since we only need to look for the SAML assertion in a single, predictable tag, `<input name="SAMLResponse"...`, the results are a lot more stable across any changes that Okta may make to their interface.

## Python Support
This project is written for Python 3. Running it with Python 2 may work, but it is not supported. Since Python 2 is end-of-life (as of 2020-JAN-01), feature requests and PRs to add Python 2 support will likely not be accepted, outside of extreme circumstances.

## Installation

- `pip3 install okta-awscli`
  - To install with U2F support (Yubikey): `pip3 install "okta-awscli[U2F]"`
- Execute `okta-awscli --config` and follow the steps to configure your Okta profile OR
- Configure okta-awscli via the `~/.okta-aws` file with the following parameters:

```
[default]
base-url = <your_okta_org>.okta.com

## The remaining parameters are optional.
## You may be prompted for them, if they're not included here.
username = <your_okta_username>
password = <your_okta_password> # Only save your password if you know what you are doing!
factor   = <your_preferred_mfa_factor> # Current choices are: GOOGLE or OKTA
role     = <your_preferred_okta_role> # AWS role name (match one of the options prompted for by "Please select the AWS role" when this parameter is not specified
profile  = <aws_profile_to_store_credentials> # Sets your temporary credentials to a profile in `.aws/credentials`. Overridden by `--profile` command line flag
app-link = <app_link_from_okta> # Found in Okta's configuration for your AWS account.
duration = 3600 # duration in seconds to request a session token for, make sure your accounts (both AWS itself and the associated okta application) allow for large durations. default: 3600
```

## Supported Features

- Tenant wide MFA support
- Per-application MFA support (added in version 0.4.0)
- Okta Verify [Play Store](https://play.google.com/store/apps/details?id=com.okta.android.auth) | [App Store](https://itunes.apple.com/us/app/okta-verify/id490179405)
- Okta Verify Push Support
- Google Authenticator [Play Store](https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2) | [App Store](https://itunes.apple.com/us/app/google-authenticator/id388497605)
- YubiKey (Requires library python-u2flib-host)  [HomePage](https://www.yubico.com/)

## Usage

`okta-awscli --profile <aws_profile> <awscli action> <awscli arguments>`
- Follow the prompts to enter MFA information (if required) and choose your AWS app and IAM role.
- Subsequent executions will first check if the STS credentials are still valid and skip Okta authentication if so.
- Multiple Okta profiles are supported, but if none are specified, then `default` will be used.
- Selections for AWS App and AWS Role are saved to the `~/.okta-aws` file. Removing the `app-link` and `role` fields will enable the prompts for these selections.

### Example

`okta-awscli --profile my-aws-account iam list-users`

If no awscli commands are provided, then okta-awscli will simply output STS credentials to your credentials file, or console, depending on how `--profile` is set.

Optional flags:
- `--profile` or `-p` Sets your temporary credentials to a profile in `.aws/credentials`. If omitted and not configured in `~/.okta-aws`, credentials will output to console.
- `--username` or `-U` Okta username.
- `--password` or `-P` Okta password.
- `--force` or `-f` Ignores result of STS credentials validation and gets new credentials from AWS. Used in conjunction with `--profile`.
- `--verbose` or `-v` More verbose output.
- `--debug` or `-d` Very verbose output. Useful for debugging.
- `--cache` or `-c` Cache the acquired credentials to ~/.okta-credentials.cache (only if --profile is unspecified)
- `--okta-profile` or `-o` Use a Okta profile, other than `default` in `.okta-aws`. Useful for multiple Okta tenants.
- `--token` or `-t` Pass in the TOTP token from your authenticator
- `--refresh-role` or `-r` Refresh the AWS role to be assumed. Previously incorporated in `--force`.
- `--lookup` or `-l` Lookup and return the AWS Account Alias for each role, instead of returning the raw ARN. 
- `--config` Add/Create new Okta profile configuration.
- `-s` or `--switch` Switch to any existing profile and update credentials.
  - Note that this will attempt to perform `iam:ListAccountAliases` on every account that you have access to via Okta. This is important for two reasons:
    - All of your roles must have this permission attached to it via an IAM policy.
    - This may be important for you, if you have compliance considerations around only accessing accounts that you're actively doing work in.
- `--version` or `-V` Outputs version number then exits.

## Run from docker container
This process is taken from gimme-aws-creds and adapted

### Build the image 
```
docker build -t okta-awscli .

```
### Run the image with the command

```
docker run -it --rm -v ~/.aws/credentials:/root/.aws/credentials -v ~/.okta-aws:/root/.okta-aws --profile default okta-awscli iam list-users
```

### if you want to type less you can create an alias

```
alias okta-awscli='docker run -it --rm -v ~/.aws:/root/.aws -v ~/.okta-aws:/root/.okta-aws okta-awscli'
```

and just type 
```
okta-awscli
```

you can add this to you .bashrc 
```
source <PATH TO GIT REPO>/set-alias.bash
```
