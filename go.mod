module github.com/morningconsult/docker-credential-vault-login

go 1.14

replace github.com/hashicorp/vault/api => github.com/hashicorp/vault/api v0.0.0-20200718022110-340cc2fa263f

require (
	github.com/docker/docker-credential-helpers v0.6.3
	github.com/google/go-cmp v0.4.0
	github.com/hashicorp/go-hclog v0.14.1
	github.com/hashicorp/go-uuid v1.0.2
	github.com/hashicorp/vault v1.5.0
	github.com/hashicorp/vault/api v1.0.5-0.20200630205458-1a16f3c699c6
	github.com/hashicorp/vault/sdk v0.1.14-0.20200718021857-871b5365aa35
	github.com/mitchellh/go-homedir v1.1.0
	github.com/morikuni/aec v1.0.0 // indirect
	golang.org/x/xerrors v0.0.0-20191204190536-9bdfabe68543
	gotest.tools/v3 v3.0.2 // indirect
)
