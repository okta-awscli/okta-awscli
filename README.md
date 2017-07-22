# okta_awscli

Authenticates a user against Okta and then retrieves temporary STS credentials from AWS.

Largely inspired by https://github.com/nimbusscale/okta_aws_login, but uses a purely API-driven approach, instead of parsing HTML during the auth phase.

Supports MFA if it is enabled for the entire Okta tenant. MFA that is required "per app", is not supported.

Usage:

- First, create a .okta-aws file in your home directory, with the following parameters:
```
[default]
base-url = <your_okta_org>.okta.com
username = <your_okta_username>
password = <your_okta_password>
```
Note: Multiple Okta profiles are supported, but if none are specified, then "default" will be used.

- `./okta_aws.py`
- Follow the prompts to enter MFA information (if required) and choose your AWS app.

## To-do:
- Support username and password as command line args.
- Add checking for validity of existing STS credentials.
- Add "wrapper" functionality, so awscli commands can be passed through.
