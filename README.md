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
* **[VAULT_ADDR](https://www.vaultproject.io/docs/commands/index.html#vault_addr)**
* **[VAULT_TOKEN](https://www.vaultproject.io/docs/commands/index.html#vault_token)**
* DOCKER_CREDS_VAULT_PATH

If your Vault instance uses TLS, you must also set the following environment variables:
* [VAULT_CACERT](https://www.vaultproject.io/docs/commands/index.html#vault_cacert)
* [VAULT_CLIENT_CERT](https://www.vaultproject.io/docs/commands/index.html#vault_client_cert) 
* [VAULT_CLIENT_KEY](https://www.vaultproject.io/docs/commands/index.html#vault_client_key)


- Users specify path where Docker credentials are stored in Vault with DOCKER_CREDS_VAULT_PATH environment variable

