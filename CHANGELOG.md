# Changelog

## [0.2.0] TBD
### Added:
- Ability to store MFA factor choice in `~/.okta-aws`. (#3)

## [0.1.4] 2017-08-27
### Added:
- This CHANGELOG!

### Fixed:
- Issue #1. Bug where MFA factor selected isn't always the one passed to Okta for verification.


## [0.1.3] 2017-08-17
### Added:
- Prompts for a username and password if omitted from `.okta-aws`

### Changed:
- Spelling fix
- Change `--okta_profile` flag to be `--okta-profile` instead.


## [0.1.2] 2017-07-25
### Added:
- Support for flag to force new credentials.

### Changed
- Handles no profile provided.
- Handles no awscli args provided (authenticate only).


## [0.1.1] 2017-07-25
- Initial release. Updated for PyPi.
