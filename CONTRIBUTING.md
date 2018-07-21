## Contributing

Contributions are always welcome!

We only ask that you follow the guidelines before before submitting your Pull Request.

- Fork and then clone the repo:
```
git clone git@github.com:your-username/okta-awscli.git
```

- Create a `~/.okta-aws` file, per the README.

It's highly recommended to use virtualenv!

- Install the project from the repo, do not use the PyPi instructions in the README.
```
pip install .
```

- Ensure that you can run pylint against your code and no errors are returned. Pull Requests with pylint errors will be rejected.

  - Currently, automated builds are only checking for actual errors, as there are some refactoring and other such notices that need to be resolved.
  - You can safely run `pylint --errors-only oktaawscli` to replicate what the build will be checking.

- Increment the version in `oktaawscli/version.py`, according to [SemVer](https://semver.org/).

- Be sure to document your changes in CHANGELOG.

- If you're adding functionality, be sure to update the README with your improvements.

- Submit a Pull Request against the `develop` branch.
