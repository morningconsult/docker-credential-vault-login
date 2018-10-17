# Docker Credential Helper for Vault-stored Credentials

![Vocker](doc/vault.png)

[![Build Status](https://ci.morningconsultintelligence.com/api/v1/teams/oss/pipelines/docker-credential-vault-login/jobs/build-release/badge)](https://ci.morningconsultintelligence.com/teams/oss/pipelines/docker-credential-vault-login)

This program is a [Docker credential helper](https://github.com/docker/docker-credential-helpers) for the Docker daemon. It automatically retrieves Docker credentials stored in [Vault](https://www.vaultproject.io/) and uses them to log in to your Docker registry when you call `docker pull`.

## Prerequisites

You must have Docker (version 1.11 or newer) and Go (version **1.10** or newer) installed on your system.

You must also have an operational instance of Vault (version 0.10 or newer).

Within Vault, you should store your Docker credentials in the following format:
```json
{
  "username": "docker@registry.user",
  "password": "my-secure-password"
}
```
Note that the Vault path where you store these credentials will be used as the value of the `secret_path` field of your `config.json` file (see the [Configuration File](#configuration-file) section).

## Installation

### Manually

You can download your preferred variant of the binary from the [releases page](https://github.com/morningconsult/docker-credential-vault-login/releases).

### Using `go get`

You can install this via `go get` with:
```bash
$ go get -u github.com/morningconsult/docker-credential-vault-login/vault-login/cli/docker-credential-vault-login
```

Once finished, the binary `docker-credential-vault-login` will be in `$GOPATH/bin`.

### Using Docker

If you do not have Go installed locally, you can still build the binary if you have Docker installed. Simply clone this repository and run `make docker` to build the binary within the Docker container and output it to the local directory.

You can cross-compile the binary using the `TARGET_GOOS` and `TARGET_GOARCH` environment variables. For example, if you wish to compile the binary for a 64-bit (x86-64) Windows machine, run the following command:

```shell
$ TARGET_GOOS="windows" TARGET_GOARCH="amd64" make docker
```

The binary will be output to `bin/local` of the local directory.

## Setup

### Docker configuration

Once you have the `docker-credential-vault-login` binary, place it on your `PATH` and set the contents of your `~/.docker/config.json` file to be:

```json
{
  "credsStore": "vault-login"
}
```

This configures the Docker daemon to use the credential helper for all registries.

With Docker 1.13.0 or greater, you can configure Docker to use different credential helpers for different registries. To use this credential helper for a specific registry, create a credHelpers section with the URI of your registry:
```json
{
  "credHelpers": {
    "my.docker.registry.com": "vault-login"
  }
}
```

## Configuration File

This application requires a configuration file `config.json` in order to determine which authentication method to use. At runtime, the process will first search for this file at the path specified by `DOCKER_CREDS_CONFIG_FILE` environmental variable. If this environmental variable is not set, it will search for it at the default path `/etc/docker-credential-vault-login/config.json`. If the configuration file is found in neither location, the process will fail.

```json
{
  "auth": {
    "method": "iam",
    "role": "dev-role-iam",
    "iam_server_id_header": "vault.service.consul"
  },
  "cache": {
    "dir": "/tmp/.docker-credential-vault-login"
  },
  "client": {
    "vault_addr": "https://vault.service.consul",
    "vault_cacert": "/tmp/cacert.pem",
    "vault_client_cert": "/tmp/client.pem",
    "vault_client_key": "/tmp/client-key.pem",
    "vault_tls_server_name": "my.server.name"
  },
  "secret_path": "secret/docker/creds"
}
```

### Configuration File Parameters

* `auth` ([Auth](#auth-parameters): `nil`) - Specifies parameters related to the method of authorization. See the [Auth](#auth-parameters) section for more details. This section is required.
* `cache` ([Cache](#cache-parameters): `nil`) - Specifies caching behavior, including where logs/tokens should be stored and whether Vault tokens should be cached. See the [Cache](#cache-parameters) section for more details. This field is optional.
* `client` ([Client](#client-parameters): `nil`) - Configures the Vault client that will be used to communicate with your Vault server. These can be overridden using the standard [Vault environment variables](https://www.vaultproject.io/docs/commands/index.html#environment-variables). See the [Client](#client-parameters) section for more details. This section is optional.
* `secret_path` (string: `""`) - Path to the secret where your Docker credentials are stored in your Vault instance (e.g. `secret/credentials/docker/myregistry`). This field is always required.

### `auth` Parameters

* `method` (string: `""`) - The method by which this application should authenticate against Vault. The only values that are accepted are `iam`, `ec2`, or `token`. If `token` is used as the authentication method, the application will use the Vault token specified by the `VAULT_TOKEN` environment variable to authenticate or the value of the `vault_token` field of the client stanza of the `config.json` file. If the `iam` method is used, it will retrieve your AWS credentials and use them to log into Vault in order to obtain a Vault token (see the [IAM authentication section](#iam-authentication-method)). If `ec2` is used, it will retrieve the PKCS7 signature from the EC2 instance's metadata and log into Vault with it in order to obtain a token (see the [EC2 authentication section](#ec2-authentication-method)). If either the `iam` or `ec2` method is chosen, be sure to [configure AWS authentication in Vault](https://www.vaultproject.io/docs/auth/aws.html#authentication). This field is always required.
* `role` (string: `""`) - Name of the Vault role against which the login is being attempted. Be sure you have [configured the policies](https://www.vaultproject.io/docs/auth/aws.html#configure-the-policies-on-the-role-) on this role accordingly. This field is only required when using the `iam` and `ec2` authentication methods.
* `iam_server_id_header` (string: `""`) - The value of the `X-Vault-AWS-IAM-Server-ID` header to be included in the AWS `sts:GetCAllerIdentity` login request (to prevent certain types of replay attacks). See the [documentation](https://www.vaultproject.io/docs/auth/aws.html#iam-auth-method) for more information on this header. This field is optional and will only be used when using the `iam` authentication method.
* `aws_mount_path` (string: `"aws"`) - The mount path of your Vault server's AWS secrets engine. This field is optional. If omitted, it will default to `"aws"`. This field is optional and will only be used when using the `iam` and `ec2` authentication methods.

### `cache` Parameters

* `dir` (string: `"~/.docker-credential-vault-login"`) - The directory where logs and tokens will be stored. The value of this field can be overridden by setting the `DOCKER_CREDS_CACHE_DIR` environment variable.
* `disable_token_caching` (bool: `false`) - Whether tokens issued by your Vault server after successful authentication should be written to disk ("cached") for future use. Enabling caching avoids the need to re-authenticate every time the binary is executed. The value of this field can be overridden by setting the `DOCKER_CREDS_DISABLE_CACHE` environment variable.

### `client` Parameters

Note: All of these parameters will be overridden by setting their corresponding [Vault environment variables](https://www.vaultproject.io/docs/commands/index.html#environment-variables).
* `vault_addr` (string: `"https://127.0.0.1:8200/"`) - Address of the Vault server expressed as a URL and port.
* `vault_token` (string: `""`) - Vault authentication token. This token will only be used when the `token` authentication method is chosen.
* `vault_cacert` (string: `""`) - Path to a PEM-encoded CA certificate file on the local disk. This file is used to verify the Vault server's SSL certificate.
* `vault_client_cert` (string: `""`) - Path to a PEM-encoded client certificate on the local disk. This file is used for TLS communication with the Vault server.
* `vault_client_key` (string: `""`) - Path to an unencrypted, PEM-encoded private key on disk which corresponds to the matching client certificate.
* `vault_tls_server_name` (string: `""`) - Name to use as the SNI host when connecting via TLS.
* `vault_client_timeout` (string: `"60s"`) - Timeout variable. This can be in seconds (e.g. "60s"), minutes (e.g. "10m"), or hours (e.g. "1h").
* `vault_skip_verify` (bool: `false`) - Do not verify Vault's presented certificate before communicating with it. Setting this variable is not recommended.
* `vault_max_retries` (int: `2`) - Maximum number of retries when a 5xx error code is encountered. Set this to 0 to or less to disable retrying.

## Usage

### EC2 Authentication Method

If the `ec2` authentication is chosen, the process will attempt to authenticate against Vault using Vault's [EC2 auth method](https://www.vaultproject.io/docs/auth/aws.html#ec2-auth-method). Specifically, it will attempt to obtain the PKCS#7 signature from the EC2 instance metadata and authenticate against Vault with it. Be sure that the instance on which this application will run is indeed an EC2 instance and that the Vault role given in the `role` field of the `config.json` file is bound to the AMI ID of the instance and that it has permission to authenticate via the EC2 method (see this [example](https://www.vaultproject.io/docs/auth/aws.html#configure-the-policies-on-the-role-)). 

### IAM Authentication Method

If the `iam` method of authentication is chosen, the process will attempt to authenticate against Vault using Vault's [IAM auth method](https://www.vaultproject.io/docs/auth/aws.html#iam-auth-method). As such, it will require IAM credentials. You also have AWS credentials available in one of the standard locations:
* The `~/.aws/credentials` file
* The `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` environment variables
* An [IAM role for Amazon EC2](http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html)

### Environmental Variables

There are also a few optional application-specific environment variables which configure the its behavior:
* **DOCKER_CREDS_CONFIG_FILE** (default: `"/etc/docker-credential-vault-login/config.json"`) - The path to your `config.json` file.
* **DOCKER_CREDS_CACHE_DIR** (default: `"~/.docker-credential-vault-login"`) - The location at which error logs and cached tokens (if caching is enabled) will be stored.
* **DOCKER_CREDS_DISABLE_CACHE** (default: `"false"`) - If `true`, the application will not cache Vault client tokens. Tokens are cached at the `tokens` subfolder of the directory given by the `DOCKER_CREDS_CONFIG_FILE` environment variable (if set), and at `~/.docker-credential-vault-login/tokens.json` if not set.

## Error Logs

All error logs will be output to `~/.docker-credential-vault-login/log/vault-login.log` by default. If you wish to store logs in a different directory, you can specify the desired directory with the `DOCKER_CREDS_CACHE_DIR` environmental variable.