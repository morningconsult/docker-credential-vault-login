module github.com/morningconsult/docker-credential-vault-login

go 1.12

replace git.apache.org/thrift.git => github.com/apache/thrift v0.12.0

require (
	github.com/aws/aws-sdk-go v1.24.0
	github.com/docker/docker-credential-helpers v0.6.3
	github.com/google/go-cmp v0.3.1
	github.com/hashicorp/go-hclog v0.9.2
	github.com/hashicorp/go-uuid v1.0.1
	github.com/hashicorp/vault v1.2.3
	github.com/hashicorp/vault/api v1.0.5-0.20190909201928-35325e2c3262
	github.com/hashicorp/vault/sdk v0.1.14-0.20190909201848-e0fbf9b652e2
	github.com/mitchellh/go-homedir v1.1.0
	golang.org/x/xerrors v0.0.0-20190717185122-a985d3407aa7
)
