module github.com/morningconsult/docker-credential-vault-login

go 1.12

replace git.apache.org/thrift.git => github.com/apache/thrift v0.12.0

require (
	github.com/aws/aws-sdk-go v1.24.0 // indirect
	github.com/docker/docker-credential-helpers v0.6.3
	github.com/google/go-cmp v0.3.1
	github.com/hashicorp/go-hclog v0.9.2
	github.com/hashicorp/go-uuid v1.0.1
	github.com/hashicorp/vault v1.2.4-0.20191017191030-0b215ea48090
	github.com/hashicorp/vault/api v1.0.5-0.20191017185408-8c0e790cc8e1
	github.com/hashicorp/vault/sdk v0.1.14-0.20191017185138-b26379d8fedc
	github.com/mitchellh/go-homedir v1.1.0
	golang.org/x/xerrors v0.0.0-20190717185122-a985d3407aa7
)
