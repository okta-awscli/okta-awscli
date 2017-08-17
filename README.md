# okta_awscli

Authenticates a user against Okta and then uses the resulting SAML assertion to retrieve temporary STS credentials from AWS.

This project is largely inspired by https://github.com/nimbusscale/okta_aws_login, but instead uses a purely API-driven approach, instead of parsing HTML during the authentication phase.

Parsing the HTML is still required to get the SAML assertion, after authentication is complete. However, since we only need to look for the SAML assertion in a single, predictable tag, `<input name="SAMLResponse"...`, the results are a lot more stable across any changes that Okta may make to their interface.

*okta_awscli supports MFA if it is enabled for the entire Okta tenant.*
*MFA that is required "per app", is not supported.*

Installation:
- `pip install okta-awscli`

Usage:

- First, create a `~/.okta-aws` file, with the following parameters:
```
[default]
base-url = <your_okta_org>.okta.com
username = <your_okta_username>
password = <your_okta_password>
```

If you omit a username or password from the config file. okta-awscli will prompt you for it.

Note: Multiple Okta profiles are supported, but if none are specified, then `default` will be used.

- `okta-awscli --profile <aws_profile> <awscli action> <awscli arguments>`
- Follow the prompts to enter MFA information (if required) and choose your AWS app and IAM role.
- Subsequent executions will first check if the STS credentials are still valid and skip Okta authentication if so.

Example:
`okta-awscli --profile my-aws-account iam list-users`

If no awscli commands are provided, then okta-awscli will simply output STS credentials to your credentials file, or console, depending on how `--profile` is set.

Optional flags:
- `--profile` Sets your temporary credentials to a profile in `.aws/credentials`. If omitted, credentials will output to console.
- `--force` Ignores result of STS credentials validation and gets new credentials from AWS. Used in conjunction with `--profile`.
- `--verbose` Verbose output. Useful for debugging.
- `--okta-profile` Use a Okta profile, other than `default` in `.okta-aws`. Useful for multiple Okta tenants.
