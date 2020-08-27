module github.com/morningconsult/docker-credential-vault-login

go 1.15

replace github.com/hashicorp/vault/api => github.com/hashicorp/vault/api v1.0.5-0.20200717191844-f687267c8086

require (
	github.com/docker/docker-credential-helpers v0.6.3
	github.com/google/go-cmp v0.5.2
	github.com/hashicorp/go-hclog v0.14.1
	github.com/hashicorp/go-uuid v1.0.2
	github.com/hashicorp/vault v1.5.2
	github.com/hashicorp/vault/api v1.0.5-0.20200630205458-1a16f3c699c6
	github.com/hashicorp/vault/sdk v0.1.14-0.20200718021857-871b5365aa35
	github.com/mitchellh/go-homedir v1.1.0
	github.com/morikuni/aec v1.0.0 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1
	gotest.tools/v3 v3.0.2 // indirect
)
