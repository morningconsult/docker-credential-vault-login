<a name="unreleased"></a>
## [Unreleased]


<a name="v0.3.19"></a>
## [v0.3.19] - 2021-12-22
### Chore
- Bump version and update changelog
- upgrade to vault 1.9.2 ([#75](https://gitlab.morningconsult.com/mci/docker-credential-vault-login/issues/75))


<a name="v0.3.18"></a>
## [v0.3.18] - 2021-08-17
### Chore
- Bump version and update changelog
- increase default timeout to 30s ([#73](https://gitlab.morningconsult.com/mci/docker-credential-vault-login/issues/73))


<a name="v0.3.17"></a>
## [v0.3.17] - 2021-08-05
### Chore
- Bump version and update changelog
- Fix go module resolutions ([#71](https://gitlab.morningconsult.com/mci/docker-credential-vault-login/issues/71))


<a name="v0.3.16"></a>
## [v0.3.16] - 2021-04-28
### Chore
- Bump version and update changelog


<a name="v0.3.15"></a>
## [v0.3.15] - 2021-04-28
### Chore
- Bump version and update changelog


<a name="v0.3.14"></a>
## [v0.3.14] - 2021-03-25
### Chore
- Bump version and update changelog
- Update to go 1.16 ([#65](https://gitlab.morningconsult.com/mci/docker-credential-vault-login/issues/65))


<a name="v0.3.13"></a>
## [v0.3.13] - 2021-03-25
### Chore
- Bump version and update changelog
- update vault dependency to 1.7.0 ([#64](https://gitlab.morningconsult.com/mci/docker-credential-vault-login/issues/64))


<a name="v0.3.12"></a>
## [v0.3.12] - 2021-03-10
### Chore
- Bump version and update changelog
- Remove ci skip from bump so release will run


<a name="v0.3.11"></a>
## [v0.3.11] - 2021-03-10
### Chore
- Bump version and update changelog [ci skip]
- Fix inclusify changes


<a name="v0.3.10"></a>
## [v0.3.10] - 2020-12-01
### Chore
- Bump version and update changelog [ci skip]
- Fix bump workflow step for git
- update vault deps to 1.6.0


<a name="v0.3.9"></a>
## [v0.3.9] - 2020-08-27
### Chore
- Bump version and update changelog [ci skip]
- Address some linting issues
- Bump Go Docker images to 1.15

### Deps
- Bump go to v1.15
- Vault[@1](https://gitlab.morningconsult.com/1).5.2


<a name="v0.3.8"></a>
## [v0.3.8] - 2020-07-21
### Chore
- Bump version and update changelog [ci skip]


<a name="v0.3.7"></a>
## [v0.3.7] - 2020-07-13
### Chore
- Bump version and update changelog [ci skip]
- Fix goreleaser


<a name="v0.3.6"></a>
## [v0.3.6] - 2020-07-13
### Chore
- Bump version and update changelog [ci skip]

### Ci
- Switch to using github workflows


<a name="v0.3.5"></a>
## [v0.3.5] - 2020-03-21
### Chore
- Bump version and update changelog [ci skip]
- go mod tidy


<a name="v0.3.4"></a>
## [v0.3.4] - 2020-03-20
### Chore
- Bump version and update changelog [ci skip]


<a name="v0.3.3"></a>
## [v0.3.3] - 2020-02-26
### Chore
- Bump version and update changelog [ci skip]
- go mod tidy


<a name="v0.3.2"></a>
## [v0.3.2] - 2020-02-26
### Chore
- Bump version and update changelog [ci skip]


<a name="v0.3.1"></a>
## [v0.3.1] - 2019-12-02
### Chore
- Bump version and update changelog [ci skip]


<a name="v0.3.0"></a>
## [v0.3.0] - 2019-11-22
### Chore
- Bump version and update changelog [ci skip]
- Maintain backwards compatibility with DCVL_DH_PRIV_KEY env var

### Feat
- Allow different environment variables for multiple Diffie-Hellman keys


<a name="v0.2.19"></a>
## [v0.2.19] - 2019-11-15
### Chore
- Bump version and update changelog [ci skip]


<a name="v0.2.18"></a>
## [v0.2.18] - 2019-10-28
### Chore
- Bump version and update changelog [ci skip]


<a name="v0.2.17"></a>
## [v0.2.17] - 2019-10-25
### Chore
- Bump version and update changelog [ci skip]


<a name="v0.2.16"></a>
## [v0.2.16] - 2019-10-25
### Chore
- Bump version and update changelog [ci skip]

### Ci
- Make merge requests public [ci skip]


<a name="v0.2.15"></a>
## [v0.2.15] - 2019-10-23
### Chore
- Bump version and update changelog [ci skip]
- Update github.com/hashicorp/vault to branch rel-1.2.4 so that the AWS region can be specified in the configuration file


<a name="v0.2.14"></a>
## [v0.2.14] - 2019-10-02
### Chore
- Bump version and update changelog [ci skip]


<a name="v0.2.13"></a>
## [v0.2.13] - 2019-09-30
### Chore
- Bump version and update changelog [ci skip]
- Update README to reflect new optional sink feature

### Feat
- Sinks are now optional


<a name="v0.2.12"></a>
## [v0.2.12] - 2019-09-26
### Chore
- Bump version and update changelog [ci skip]


<a name="v0.2.11"></a>
## [v0.2.11] - 2019-09-25
### Chore
- Bump version and update changelog [ci skip]
- Make a change so CI picks it up
- Point badge to correct URL [ci skip]
- Update README [ci skip]


<a name="v0.2.10"></a>
## [v0.2.10] - 2019-09-25
### Chore
- Bump version and update changelog [ci skip]
- Refactor helper, reduce cyclomatic complexity, and general linting
- Reduce cyclomatic complexity of GetCachedTokens
- Migrate from dep to Go modules and begin major renovation


<a name="v0.2.9"></a>
## [v0.2.9] - 2019-04-13
### Ci
- More fixes to pr resources
- need to let github know tests are pending
- clean up some pipeline stuff

### Deps
- Update vault client to 1.1.1

### Docker
- Update golang version to 1.11.4


<a name="v0.2.8"></a>
## [v0.2.8] - 2019-01-07

<a name="v0.2.7"></a>
## [v0.2.7] - 2019-01-07
### Ci
- Fix build-release script


<a name="v0.2.6"></a>
## [v0.2.6] - 2019-01-06
### Ci
- Run tests as non-root


<a name="v0.2.5"></a>
## [v0.2.5] - 2019-01-06

<a name="v0.2.4"></a>
## [v0.2.4] - 2019-01-05

<a name="v0.2.3"></a>
## [v0.2.3] - 2019-01-05

<a name="v0.2.2"></a>
## [v0.2.2] - 2019-01-05

<a name="v0.2.1"></a>
## [v0.2.1] - 2019-01-05

<a name="v0.2.0"></a>
## [v0.2.0] - 2019-01-05
### Chore
- Added license headers
- Added license header to all files
- go fmt
- go fmt

### Helper
- Increased test coverage
- Increased test coverage
- Wrote some unit tests
- Added tests

### Makefile
- minor syntax changes
- Modified build target to reflect project structure change


<a name="v0.1.15"></a>
## [v0.1.15] - 2018-12-04
### Vendor
- Updated deps
- Updated deps


<a name="v0.1.14"></a>
## [v0.1.14] - 2018-10-23

<a name="v0.1.13"></a>
## [v0.1.13] - 2018-10-18

<a name="v0.1.12"></a>
## [v0.1.12] - 2018-10-16

<a name="v0.1.11"></a>
## [v0.1.11] - 2018-10-16
### Chore
- cleanup after tests


<a name="v0.1.10"></a>
## [v0.1.10] - 2018-10-16

<a name="v0.1.9"></a>
## [v0.1.9] - 2018-10-10

<a name="v0.1.8"></a>
## [v0.1.8] - 2018-10-09

<a name="v0.1.7"></a>
## [v0.1.7] - 2018-10-09

<a name="v0.1.6"></a>
## [v0.1.6] - 2018-10-09

<a name="v0.1.5"></a>
## [v0.1.5] - 2018-10-09

<a name="v0.1.4"></a>
## [v0.1.4] - 2018-10-09

<a name="v0.1.3"></a>
## [v0.1.3] - 2018-10-09

<a name="v0.1.2"></a>
## [v0.1.2] - 2018-10-09

<a name="v0.1.1"></a>
## [v0.1.1] - 2018-10-09
### Chore
- resolved merge conflicts
- Formatted .go files

### Makefile
- Added targets for concourse


<a name="v0.1.0"></a>
## [v0.1.0] - 2018-10-09

<a name="v0.0.1"></a>
## v0.0.1 - 2018-10-08
### Aws
- Added testing

### Chore
- Added check for non-nil errors when appropriate in some unit tests
- Formatted files
- Ran a `go fmt`
- Added license header to all files; vault-login/cache/cache.go: Added encryption functionality; vault-login/cache/cache_test.go: Added tests for encryption functionality
- Added more unit test coverage
- More formatting
- Formatted spacing
- Add more tests to increase test coverage
- Added support for EC2 authentication method
- Increased test coverage
- Added more unit tests and cleaned up unused files
- Removed AWS client mocks
- Added AWS client mocks
- resolved merge conflicts (refactor -> master)
- Improved make target for building binary in Docker and wrote more tests

### Ci
- Fix incorrect ld flag
- Dont let shit expire
- Just make the single binary the artifact
- Use more specific artificat
- Add ldflags to built artificat
- Add a basic gitlab ci file

### Makefile
- Fixed error in `test` target; ci/pipeline.yml: Run test PR on golang:1.11-alpine3.8; ci/run-tests.sh: Trimmed some of the unnecessary stuff
- echo statements don't create weird files now
- added make target to sync vault/version/version.go with current version

### README
- Added testing instructions

### Vendor
- Updated deps
- consolidated vendor into one directory
- deleted vendor temporarily
- Updated vendor files
- Updated deps
- Pruned vendors
- Updated strutil
- trying to update deps

### Reverts
- Merge branch 'master' of gitlab.morningconsult.com:mci/docker-credential-vault-login

### Merge Requests
- Merge branch 'revert-2f1900fa' into 'master'
- Merge branch 'ad-gitlab-ci' into 'master'


[Unreleased]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.3.19...HEAD
[v0.3.19]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.3.18...v0.3.19
[v0.3.18]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.3.17...v0.3.18
[v0.3.17]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.3.16...v0.3.17
[v0.3.16]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.3.15...v0.3.16
[v0.3.15]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.3.14...v0.3.15
[v0.3.14]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.3.13...v0.3.14
[v0.3.13]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.3.12...v0.3.13
[v0.3.12]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.3.11...v0.3.12
[v0.3.11]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.3.10...v0.3.11
[v0.3.10]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.3.9...v0.3.10
[v0.3.9]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.3.8...v0.3.9
[v0.3.8]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.3.7...v0.3.8
[v0.3.7]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.3.6...v0.3.7
[v0.3.6]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.3.5...v0.3.6
[v0.3.5]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.3.4...v0.3.5
[v0.3.4]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.3.3...v0.3.4
[v0.3.3]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.3.2...v0.3.3
[v0.3.2]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.3.1...v0.3.2
[v0.3.1]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.3.0...v0.3.1
[v0.3.0]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.2.19...v0.3.0
[v0.2.19]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.2.18...v0.2.19
[v0.2.18]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.2.17...v0.2.18
[v0.2.17]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.2.16...v0.2.17
[v0.2.16]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.2.15...v0.2.16
[v0.2.15]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.2.14...v0.2.15
[v0.2.14]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.2.13...v0.2.14
[v0.2.13]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.2.12...v0.2.13
[v0.2.12]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.2.11...v0.2.12
[v0.2.11]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.2.10...v0.2.11
[v0.2.10]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.2.9...v0.2.10
[v0.2.9]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.2.8...v0.2.9
[v0.2.8]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.2.7...v0.2.8
[v0.2.7]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.2.6...v0.2.7
[v0.2.6]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.2.5...v0.2.6
[v0.2.5]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.2.4...v0.2.5
[v0.2.4]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.2.3...v0.2.4
[v0.2.3]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.2.2...v0.2.3
[v0.2.2]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.2.1...v0.2.2
[v0.2.1]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.2.0...v0.2.1
[v0.2.0]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.1.15...v0.2.0
[v0.1.15]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.1.14...v0.1.15
[v0.1.14]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.1.13...v0.1.14
[v0.1.13]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.1.12...v0.1.13
[v0.1.12]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.1.11...v0.1.12
[v0.1.11]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.1.10...v0.1.11
[v0.1.10]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.1.9...v0.1.10
[v0.1.9]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.1.8...v0.1.9
[v0.1.8]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.1.7...v0.1.8
[v0.1.7]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.1.6...v0.1.7
[v0.1.6]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.1.5...v0.1.6
[v0.1.5]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.1.4...v0.1.5
[v0.1.4]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.1.3...v0.1.4
[v0.1.3]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.1.2...v0.1.3
[v0.1.2]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.1.1...v0.1.2
[v0.1.1]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.1.0...v0.1.1
[v0.1.0]: https://gitlab.morningconsult.com/mci/docker-credential-vault-login/compare/v0.0.1...v0.1.0
