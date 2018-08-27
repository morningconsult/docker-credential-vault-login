# Docker Credential Helper for Vault-stored Credentials

This program is a [Docker credential helper](https://github.com/docker/docker-credential-helpers) for the Docker daemon that retrieves credentials from [Vault](https://www.vaultproject.io/).

## Prerequisites

You must have Docker (version 1.11 or newer) and Go (version **1.8** or newer) installed on your system.

You must also have an operational instance of Vault (version 0.10 or newer).

Within Vault, you should store your Docker credentials in the following format:
```json
{
    "username": "docker@registry.user",
    "password": "my-secure-password"
}
```
Note that the Vault path where you store these credentials will be used as the value of the `vault_secret_path` field of your `config.json` file (see the [Configuration File](#configuration-file) section).

## Installation
Note: If you're pulling from Morning Consult's private GitLab, run the following in order to enable `go get`:
```bash
$ git config --global url."git@gitlab.morningconsult.com:".insteadOf "https://gitlab.morningconsult.com/
```

You can install this via `go get` with:
```bash
$ go get -u gitlab.morningconsult.com/mci/docker-credential-vault-login/vault-login/cli/docker-credential-vault-login
```

Once finished, the binary `docker-credential-vault-login` will be in `$GOPATH/bin`. Place the `docker-credential-vault-login` binary on your `PATH` and set the contents of your `~/.docker/config.json` file to be:

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

## Setup

### Configuration File
This program requires a configuration file `config.json` in order to determine which authentication method to use. The program will search first search for this file at the path specified with by `DOCKER_CREDS_CONFIG_FILE` environmental variable. If this environmental variable is not set, it will search for it at the default path `/etc/docker-credential-vault-login/config.json`. If the configuration file is found in neither location, it will fail.

The configuration file should include the following:
* `vault_auth_method` (string: "") - Method by which this application should authenticate against Vault. The only two values that are accepted are `aws` or `token`. If `token` is used as the authentication method, the application will use the Vault token specified by the `VAULT_TOKEN` environment variable to authenticate. If `aws` is used, the application will retrieve AWS credentials and use them to log into Vault in order to retrieve a Vault token. If the `aws` method is chosen, be sure to [configure AWS authentication in Vault](https://www.vaultproject.io/docs/auth/aws.html#authentication). This field is always required.
* `vault_role` (string: "") - Name of the Vault role against which the login is being attempted. Be sure you have [configured the policies](https://www.vaultproject.io/docs/auth/aws.html#configure-the-policies-on-the-role-) on this role accordingly. This is only required when using the `aws` authentication method. 
* `vault_secret_path` (string: "") - Path to the secret at which your docker credentials are stored in your Vault instance (e.g. `secret/credentials/docker/myregistry`). This field is always required.
* `vault_iam_server_id_header_value` (string: "") - The value of the `X-Vault-AWS-IAM-Server-ID` header to be included in the AWS `sts:GetCAllerIdentity` login request (to prevent certain types of replay attacks). See the [documentation](https://www.vaultproject.io/docs/auth/aws.html#iam-auth-method) for more information on this header. This field is optional and will only be used when using the `aws` authentication method.

**Sample Configuration File**
```json
{
  "vault_auth_method": "aws",
  "vault_role": "dev-role-iam",
  "vault_secret_path": "secret/credentials/docker/myregistry",
  "vault_iam_server_id_header_value": "vault.example.com"
}
```

### AWS IAM Credentials

This program requires IAM credentials if the `aws` method of authentication is selected. You also have AWS credentials available in one of the standard locations:
* The `~/.aws/credentials` file
* The `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` environment variables
* An [IAM role for Amazon EC2](http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html)

### Environmental Variables
Additionally, in order for the helper to work properly you must first set some Vault environmental variables on your system:
* **[VAULT_ADDR](https://www.vaultproject.io/docs/commands/index.html#vault_addr)** - (Required) Your Vault instance's URL
* **[VAULT_TOKEN](https://www.vaultproject.io/docs/commands/index.html#vault_token)** - (Note: This only applies if the `token` authentication method is chosen) A valid Vault token with permission to read your secret
* **DOCKER_CREDS_CONFIG_FILE** - (Optional) The path to your `config.json` file. If not set, the program will search for the file at `/etc/docker-credential-vault-login/config.json`.

If your Vault instance uses TLS, you must also set the following environment variables:
* **[VAULT_CACERT](https://www.vaultproject.io/docs/commands/index.html#vault_cacert)**
* **[VAULT_CLIENT_CERT](https://www.vaultproject.io/docs/commands/index.html#vault_client_cert)**
* **[VAULT_CLIENT_KEY](https://www.vaultproject.io/docs/commands/index.html#vault_client_key)**

Once you've set these environmental variables, your Docker daemon will automatically look up the credentials in Vault at the path specified in the `vault_secret_path` field of your `config.json` file and use them to authenticate against your Docker registries.
