# Docker Credential Helper for Vault-stored Credentials

This program is a [Docker credential helper](https://github.com/docker/docker-credential-helpers) for the Docker daemon that retrieves credentials from [Vault](https://www.vaultproject.io/).

## Prerequisites

You must have Docker (version 1.11 or newer) and Go (version 1.6 or newer) installed on your system.

You must also have an operational instance of Vault (version 0.10 or newer).

Within Vault, you should store your Docker credentials in the following format:
```json
{
    "username": "docker@registry.user",
    "password": "my-secure-password"
}
```
Note that the Vault path where you store these credentials will be used as the value of the `DOCKER_CREDS_VAULT_PATH` environment variable (see the [Usage](#usage) section).

## Installation

You can install this via `go get` with:
```bash
$ go get -u gitlab.morningconsult.com/mci/docker-credential-vault-login
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

## Usage

In order for the helper to work properly, you must first set some Vault environmental variables on your system:
* **[VAULT_ADDR](https://www.vaultproject.io/docs/commands/index.html#vault_addr)** - Your Vault instance's URL
* **[VAULT_TOKEN](https://www.vaultproject.io/docs/commands/index.html#vault_token)** - A valid Vault token with permission to read your secret
* **DOCKER_CREDS_VAULT_PATH** - The path in your Vault instance where your Docker credentials secret is stored (e.g. `secret/credentials/docker/myregistry`)

If your Vault instance uses TLS, you must also set the following environment variables:
* **[VAULT_CACERT](https://www.vaultproject.io/docs/commands/index.html#vault_cacert)**
* **[VAULT_CLIENT_CERT](https://www.vaultproject.io/docs/commands/index.html#vault_client_cert)**
* **[VAULT_CLIENT_KEY](https://www.vaultproject.io/docs/commands/index.html#vault_client_key)**

Once you've set these environmental variables, your Docker daemon will automatically look up the credentials in Vault at the `DOCKER_CREDS_VAULT_PATH` and use them to authenticate against your Docker registries.

## Testing
**Important:** Unit tests may only be performed on 64-bit Linux machine.

In order to test this package, you must first `go get` it.
```bash
$ go get -u gitlab.morningconsult.com/mci/docker-credential-vault-login
```

Then, `cd` to this package in your `src` directory and run `make test`
```bash
$ cd $GOPATH/src/gitlab.morningconsult.com/mci/docker-credential-vault-login
$ make test
```

The test script will perform the following steps:
1. Pull a [Vault binary](https://releases.hashicorp.com/vault)
2. Start Vault in development mode
3. Execute unit tests (`go test ...`)
4. Stop Vault
5. Cleanup test files