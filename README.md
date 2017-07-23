# okta_awscli

Authenticates a user against Okta and then uses the resulting SAML assertion to retrieve temporary STS credentials from AWS.

This project is largely inspired by https://github.com/nimbusscale/okta_aws_login, but instead uses a purely API-driven approach, instead of parsing HTML during the authentication phase.

Parsing the HTML is still required to get the SAML assertion, after authentication is complete. However, since we only need to look for the SAML assertion in a single, predictable tag, `<input name="SAMLResponse"...`, the results are a lot more stable across any changes that Okta may make to their interface.

*okta_awscli supports MFA if it is enabled for the entire Okta tenant. MFA that is required "per app", is not supported.*

Usage:

- First, create a `~/.okta-aws` file, with the following parameters:
```
[default]
base-url = <your_okta_org>.okta.com
username = <your_okta_username>
password = <your_okta_password>
```
Note: Multiple Okta profiles are supported, but if none are specified, then "default" will be used.

- `./okta_aws.py --okta_profile default --profile my-aws-account`
- Follow the prompts to enter MFA information (if required) and choose your AWS app and IAM role.

## To-do:
- [x] Add checking for validity of existing STS credentials.
- [x] Add "wrapper" functionality, so awscli commands can be passed through.
- [ ] Support username and password as command line args.
