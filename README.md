# Docker Credential Helper for Vault-stored Credentials

![Vocker](doc/vault.png)

![Test](https://github.com/morningconsult/docker-credential-vault-login/workflows/Test/badge.svg)

This program is a [Docker credential helper](https://github.com/docker/docker-credential-helpers) for the Docker daemon. When you run `docker pull` it automatically authenticates to your [Vault](https://www.vaultproject.io/) server, fetches your Docker credentials, and uses those credentials to log in to your Docker registry before pulling the Docker image.

This program leverages much of the [Vault agent](https://www.vaultproject.io/docs/agent/) code for authentication. As such, it requires the same [configuration file](https://www.vaultproject.io/docs/agent/autoauth/index.html) as the Vault agent (see the [configuration file](#configuration-file) section for more information). Furthermore, it supports all of the authentication methods currently supported by the Vault agent, including:

* Alibaba Cloud (AliCloud)
* Vault AppRole
* Amazon Web Services (AWS)
* CloudFoundry (CF)
* Cert
* Microsoft Azure
* Google Cloud Platform (GCP)
* JSON Web Tokens (JWT)
* Kubernetes

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Setup](#setup)
  - [Docker Configuration](#docker-configuration)
  - [Configuration File](#configuration-file)
  - [Vault Client Configuration](#vault-client-configuration)
  - [Token Authentication](#token-authentication)
  - [Environment Variables](#environment-variables)
- [Error Logs](#error-logs)
- [Demonstration](#demonstration)
- [Frequently-Asked Questions](#frequently-asked-questions)

## Prerequisites

You must have Docker (version 1.11 or newer) and Go (version **1.11.3** or newer) installed on your system.

You must also have an operational instance of Vault (version 0.10 or newer).

Within Vault, you should store your Docker credentials in the following format:
```json
{
    "username": "docker@registry.user",
    "password": "my-secure-password"
}
```
Note that the Vault path where you store these credentials will be used as the value of the `secret` or `secrets` field of your configuration file (see the [Configuration File](#configuration-file) section).

## Installation

### Download

You can download your preferred variant of the binary from the [releases page](https://github.com/morningconsult/docker-credential-vault-login/releases).

### Build locally

If you have Go installed locally, you can build the binary yourself.

```shell
$ git clone https://github.com/morningconsult/docker-credential-vault-login
$ cd docker-credential-vault-login
$ make
```
The binary will be output to `bin` of the local directory.

### Build in Docker

If you do not have Go installed locally, you can still build the binary if you have Docker installed. Simply clone this repository and run `make docker` to build the binary within the Docker container and output it to the local directory.

You can cross-compile the binary using the `TARGET_GOOS` and `TARGET_GOARCH` environment variables. For example, if you wish to compile the binary for a 64-bit (x86-64) Windows machine, run the following command:

```shell
$ TARGET_GOOS="windows" TARGET_GOARCH="amd64" make docker
```

The binary will be output to `bin` of the local directory.

## Setup

### Docker configuration

Once you have the `docker-credential-vault-login` binary, place it in a location on your `PATH` and set the contents of your `~/.docker/config.json` file to be:

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

### Configuration File

**This application relies on the same configuration file as the [Vault agent configuration file](https://www.vaultproject.io/docs/agent/index.html) (with a few small differences). Specifically, it uses only the [`vault`](https://www.vaultproject.io/docs/agent/index.html#vault-stanza) (optional) and [`auto_auth`](https://www.vaultproject.io/docs/agent/autoauth/index.html) (required) sections of the Agent configuration file. The Vault Agent documentation will be the primary reference for how to compose this file.**

At runtime, the helper will first search for this file at the path specified by `DCVL_CONFIG_FILE` environmental variable. If this environmental variable is not set, it will search for it at the default path `/etc/docker-credential-vault-login/config.hcl`. If the configuration file is found in neither location, it will fail.

This configuration file is essentially broken into three parts:

1. An authentication method (`auto_auth.method`). This stanza directs how the helper will authenticate to your Vault instance in order to obtain a Vault client token.
1. Any number of "sinks" (`auto_auth.sink`) (which are referred to in the context of this application as "cached tokens"). These stanzas direct how the helper will store client tokens for reuse. The cached tokens prevent the need to re-authenticate each time the helper is executed.
1. An optional stanza configuring how to reach your Vault server (`vault`).

While all the rules that apply to the Vault agent configuration file apply here, there are also some additional application-specific rules:

- **Only the `auto_auth`, and `vault` stanzas are honored**. Of the various top-level elements that can be included in the file (e.g. `pid_file`, `exit_after_auth`, `auto_auth`, `vault`, `cache`, `listener`, etc.), only the `auto_auth` and `vault` stanzas are needed. All other stanzas will be ignored. The `vault` stanza is optional. The [Vault environment variables](https://www.vaultproject.io/docs/commands/#environment-variables) can be used in instead of the `vault` stanza.
- **Docker credentials secret**. The path to the secret(s) where your Docker credentials is/are kept in Vault (see the [Prerequisites](#prerequisites) section for what this secret should look like) must be specified in the configuration file. See the [Secret Path](#secret-path) section for how to specify the secret(s).
- **Sinks are optional**. Sinks are used for storing tokens for reuse later, avoiding the need to reauthenticate. They are optional. To add a sink, include it in the `auto_auth.sink` stanza. Any number of sinks may be used. If no sinks are used, then the credential helper will authenticate every time it runs in order to obtain a Vault token.
- **`token` authentication method**. In addition to the [authentication methods](https://www.vaultproject.io/docs/agent/autoauth/methods/index.html) supported by the Vault agent (e.g. `aws`, `gcp`, `alicloud`, etc.), a `token` method is also supported which allows you to bypass authentication by manually providing a valid Vault client token. See the [Token Authentication](#token-authentication) section for more information.
- **Diffie-Hellman private key**. As mentioned in [sink](https://www.vaultproject.io/docs/agent/autoauth/index.html#configuration-sinks-) section the Vault agent documentation, a Diffie-Hellman public key must be provided if you wish to encrypt tokens. However, in order to decrypt those tokens for future use, you must also provide the Diffie-Hellman private key either in the configuration file or by an environment variable (see the [Diffie-Hellman Private Key](#diffie-hellman-private-key) section).

#### Example

The configuration file shown in this example is based on an [example](https://www.vaultproject.io/docs/agent/index.html#example-configuration) provided in the Vault documentation:

```hcl
vault {
	address         = "https://example.com"
	tls_skip_verify = "true"
}

auto_auth {
	method "aws" {
		mount_path = "auth/aws"
		config = {
			type   = "iam"
			role   = "foobar"
			secret = "secret/application/docker"
		}
	}

	sink "file" {
		config = {
			path = "/tmp/file-foo"
		}
	}

	sink "file" {
		wrap_ttl = "5m"
		aad_env_var = "TEST_AAD_ENV"
		dh_type = "curve25519"
		dh_path = "/tmp/dh-pub-key.json"
		config = {
			path    = "/tmp/file-bar.json"
			dh_priv = "/tmp/dh-priv-key.json"
		}
	}
}
```

**Note**: The Diffie-Hellman public and private key files (`dh_path` and `dh_priv` fields) can be generated by executing [this](https://github.com/morningconsult/docker-credential-vault-login/blob/master/scripts/generate-dh-keys.sh) script provided in the repository. Note that this script requires version 1.11 of Go or newer.

Using this configuration file, the helper will perform the following when you run `docker pull`:

1. **Read all cached tokens ("sinks").** Specifically, the helper will read `/tmp/file-foo`, expecting this file to contain a plaintext token. Then, it will read `/tmp/file-bar.json`, decrypt it using the Diffie-Hellman public-private key pair (`/tmp/dh-pub-key.json` and `/tmp/dh-priv-key.json` respectively), and [unwrap](https://www.vaultproject.io/docs/concepts/response-wrapping.html) it to obtain a usable client token.
2. **Use a cached token to read the secret.** It will then attempt to read your read your Docker credentials from Vault at the path `secret/application/docker` with each of the cached tokens. If any of the cached tokens were successful, the helper will pass the credentials to the Docker daemon and exit.
3. **Re-authenticate if all cached tokens failed.** If the helper was unable to read the secret using any of the cached tokens, it will authenticate to your Vault instance via the [AWS IAM](https://www.vaultproject.io/docs/auth/aws.html#iam-auth-method) endpoint using the `foobar` role to obtain a new Vault client token.
4. **Use the new token to read the secret.** If authentication was successful, the helper will use the newly-obtained token to read your Docker credentials at `secret/application/docker`.
5. **Cache the new token.** If authentication was successful, the helper will also cache the tokens in the manner dictated by the `sink` stanzas of the configuration file: (1) as plaintext in a file called `/tmp/file-foo` and (2) TTL-wrapped and encrypted in a JSON file called `/tmp/file-bar.json`.

If it was able to successfully read your Docker credentials from Vault, it will pass these credentials to the Docker daemon which will then use them to login to your Docker registry before pulling your image.

#### Secret Path

The `auto_auth.method.config` field of the configuration file must contain the *either* the key `secret` whose value is the path to the secret where your Docker credentials are kept in your Vault server *or* the key `secrets` which point different registries to different secrets **BUT NOT BOTH**.

##### Single secret for all registries

If you want the helper to look for your Docker credentials at just one path in Vault, then the value of `secret` should just be a string representing the path to the secret. For example, if you keep your Docker credentials at `secret/application/docker`, you might construct your configuration file like this:

```hcl
auto_auth {
	method "aws" {
		mount_path = "auth/aws"
		config = {
			type   = "iam"
			role   = "foobar"
			secret = "secret/application/docker"
		}
	}

	sink "file" {
		config = {
			path = "/tmp/file-foo"
		}
	}
}
```

With this configuration, when you run a `docker pull`, the helper will attempt to read your secret at `secret/application/docker`, regardless of which registry is requested. In other words, if you run `docker pull registry.example.com/my-image`, `docker pull registry.foo.bar/bin-baz`, or any other registry, then the helper will attempt to lookup your Docker credentials at `secret/application/docker` every time.

##### Different secrets for different registries

You may also specify different secrets for different registries via the `secrets` field. for example, you might construct your configuration file like this:

```hcl
auto_auth {
	method "aws" {
		mount_path = "auth/aws"
		config = {
			type    = "iam"
			role    = "foobar"
			secrets = {
                                registry-1.example.com = "secret/docker/registry1"
                                registry-2.example.com = "secret/docker/registry2"
                        }
		}
	}

	sink "file" {
		config = {
			path = "/tmp/file-foo"
		}
	}
}
```

With this configuration, if you attempt to pull an image from `registry-1.example.com` (e.g. `docker pull registry-1.example.com/my-image`) then the helper will attempt to lookup your Docker credentials at `secret/docker/registry1`. On the other hand, if you were to run `docker pull registry-2.example.com/my-image`, it will attempt to lookup the credentials at `secret/docker/registry2`.

#### Diffie-Hellman Private Key

If a cached token is [encrypted](https://www.vaultproject.io/docs/agent/autoauth/index.html#encrypting-tokens), the `auto_auth.sink.config` field must contain the key `dh_priv` whose value is the path to a file containing your Diffie-Hellman private key with which the helper will decrypt the token. This file should be a JSON file structured like the one shown below:

```json
{
    "curve25519_private_key": "NXAnojBsGvT9UMkLPssHdrqEOoqxBFV+c3Bf9YP8VcM="
}
```

The private key can also be specified with an environment variable. You can set your private key to any environment variable you wish. The value should simply be the private key expressed as a base64-encoded string. The environment variable used should be specified in the `auto_auth.sink.config`' field of the configuration file. For example, let's say I want to use a different set of Diffie-Hellman keys for my sinks. For one sink, I want to set the private key to the `DCVL_DH_PRIV_KEY_1` environment variable, and for the other, I want to set it to the `DCVL_DH_PRIV_KEY_2` variable. To do this, I might write the following configuration file:

```hcl
auto_auth {
	method "aws" {
		mount_path = "auth/aws"
		config = {
			type    = "iam"
			role    = "foobar"
			secrets = {
                                registry-1.example.com = "secret/docker/registry1"
                                registry-2.example.com = "secret/docker/registry2"
                        }
		}
	}

	sink "file" {
		dh_type = "curve25519"
                dh_path = "/tmp/dh-pub-1.json"
		config  = {
			path = "/tmp/file-foo"
			dh_priv_env = "DCVL_DH_PRIV_KEY_1"
		}
	}

	sink "file" {
		dh_type = "curve25519"
                dh_path = "/tmp/dh-pub-2.json"
		config  = {
			path = "/tmp/file-foo"
			dh_priv_env = "DCVL_DH_PRIV_KEY_2"
		}
	}
}
```

Then, I would set the environment variables:

```shell
$ export DCVL_DH_PRIV_KEY_1="NXAnojBsGvT9UMkLPssHdrqEOoqxBFV+c3Bf9YP8VcM="
$ export DCVL_DH_PRIV_KEY_2="kYU15pdT5zjjJ9aLD3eG+1jljySQn47c8W+IHTgJYAA="
```

If both `dh_priv` and `dh_priv_env` are set, the environment variable takes precedence.

**Note**: For backwards compatibility, the `DCVL_DH_PRIV_KEY` environment variable is still honored. If this variable is set, then it will be used for all sinks, regardless of what you set in the `dh_priv` or `dh_priv_env` fields. Do not use this environment variable unless you are using only one Diffie-Hellman key pair for all sinks.

**Note**: You can generate a Diffie-Hellman public-private key pair with the [script](https://github.com/morningconsult/docker-credential-vault-login/blob/master/scripts/generate-dh-keys.sh) provided in this repository.

### Token Authentication

You may also manually provide a Vault client token to bypass authentication altogether. To do so, you must use `token` authentication method in your configuration file and provide the token in the `auto_auth.method.config.token` field of the configuration file or by setting the token with the `VAULT_TOKEN` environment variable. See the examples below.

#### Example 1: Token set in configuration file

You can set the token in the `auto_auth.method.config.token` field.

```hcl
auto_auth {
	method "token" {
		mount_path = "auth/token"
		config     = {
			secret = "secret/application/docker"
			token  = "8efc06ef-ced9-170f-9f66-c94740a61c93"
		}
	}

	sink "file" {
		config = {
			path = "/tmp/file-foo"
		}
	}
}
```

#### Example 2: Token set in environment

You can also set the token in `VAULT_TOKEN` environment variable.

```shell
$ export VAULT_TOKEN="8efc06ef-ced9-170f-9f66-c94740a61c93"
```

If you've set your token in the environment, you do not need to provide it in the configuration file.

```hcl
auto_auth {
	method "token" {
		mount_path = "auth/token"
		config     = {
			secret = "secret/application/docker"
		}
	}

	sink "file" {
		config = {
			path = "/tmp/file-foo"
		}
	}
}
```

### Environment Variables

This helper uses the following environment variables:

* **DCVL_CONFIG_FILE** (default: `"/etc/docker-credential-vault-login/config.hcl"`) - The path to your `config.hcl` file.
* **DCVL_LOG_DIR** (default: `"~/.docker-credential-vault-login"`) - The location at which error logs and cached tokens (if caching is enabled) will be stored.
* **DCVL_DISABLE_CACHE** (default: `"false"`) - If `true`, the helper will not cache Vault client tokens or use cached tokens to authenticate to Vault.
* **DCVL_DH_PRIV_KEY** (default: `""`) - The path to the Diffie-Hellman private key to be used to decrypt an encrypted cached token. See the [Diffie-Hellman Private Key](#diffie-hellman-private-key) section.

Note that this will honor all of the [Vault environment variables](https://www.vaultproject.io/docs/commands/#environment-variables) as well.

## Error Logs

All error logs will be output to the `~/.docker-credential-vault-login` directory by default. If you wish to store logs in a different directory, you can specify the desired directory with the `DCVL_LOG_DIR` environmental variable.

## Demonstration

This demonstration will illustrate how to use this Docker credential helper to automatically pull an image from a restricted, locally-hosted Docker registry when the credentials to the registry are stored in Vault. Vault's AppRole authentication method will be used in this demonstration.

### Setup a local Docker registry

1. Create a password file with one entry for user `testuser`, with password `testpassword`.

```shell
$ mkdir -p /tmp/auth
$ docker run \
    --entrypoint htpasswd \
    registry:2 -Bbn testuser testpassword > /tmp/auth/htpasswd
```

2. Start a Docker registry in a Docker container with basic authentication.

```shell
$ docker run \
    --detach \
    --publish 5000:5000 \
    --restart=always \
    --name registry \
    --volume /tmp/auth:/auth \
    --env "REGISTRY_AUTH=htpasswd" \
    --env "REGISTRY_AUTH_HTPASSWD_REALM=Registry Realm" \
    --env "REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd" \
    registry:2
```

3. Try to pull an image from the registry, or push an image to the registry. These commands should fail.

4. Log in to the registry.

```shell
$ docker login localhost:5000
```

Provide the username and password from the first step (`testuser` and `testpassword` respectively).

5. Copy an image from Docker Hub to your registry.

```shell
$ docker pull alpine:3.8
$ docker tag alpine:3.8 localhost:5000/my-alpine
$ docker push localhost:5000/my-alpine
```

6. Remove locally-cached `alpine:3.8` and `localhost:5000/my-alpine` images so that you can test pulling the image from your registry later. This does not remove the `localhost:5000/my-alpine` image from your registry.

```shell
$ docker image remove alpine:3.8
$ docker image remove localhost:5000/my-alpine
```

7. Remove the saved authorization from your `~/.docker/config.json` file so that the authentication can be tested later.

```shell
$ CONFIG=$( cat ~/.docker/config.json | jq -Mr 'del(.auths | ."localhost:5000")' )
$ echo $CONFIG | jq -Mr > ~/.docker/config.json
```

**Recap**
Now you have a restricted Docker registry hosted in a Docker container at `localhost:5000` with just one image: `localhost:5000/my-alpine`. In order to pull this image, you must first authenticate to the registry with a username and password. Next, we will start up a Vault server and store the Docker credentials there.

### Start a Vault server

1. Download and extract [Vault](https://www.vaultproject.io/downloads.html).

```shell
$ cd /tmp
$ wget https://releases.hashicorp.com/vault/1.2.3/vault_1.2.3_linux_amd64.zip
$ unzip vault_1.2.3_linux_amd64.zip
```

2. Start Vault in development mode

```shell
$ ./vault server -dev
```

Make a note of the Vault address and the root key. They should have been written to stdout and should look like this:

```
You may need to set the following environment variable:

    $ export VAULT_ADDR='http://127.0.0.1:8200'

The unseal key and root token are displayed below in case you want to
seal/unseal the Vault or re-authenticate.

Unseal Key: 4ZsffZK7kLB+7lkXnVNbkgsgRji23kkHEVToMK1I8NY=
Root Token: s.2SEXNmeT27KURAvSS8nMioOB
```

3. Open another terminal.

4. Set the Vault address and token environment variables.

```shell
$ cd /tmp
$ export VAULT_ADDR="http://127.0.0.1:8200"
$ export VAULT_TOKEN="s.2SEXNmeT27KURAvSS8nMioOB"
```

5. Enable the `approle` backend.

```shell
$ ./vault auth enable approle
Success! Enabled approle auth method at: approle/
```

6. Create a named role.

```shell
$ ./vault write auth/approle/role/my-role \
    secret_id_ttl=24h \
    token_num_uses=10 \
    token_ttl=20m \
    token_max_ttl=30m \
    secret_id_num_uses=40 \
    policies=default,dev-policy
Success! Data written to: auth/approle/role/my-role
```

7. Fetch the RoleID of the AppRole.

```shell
$ ./vault read auth/approle/role/my-role/role-id
Key        Value
---        -----
role_id    0b876805-aa07-3406-453f-ff0d0721770b
```

8. Get a SecretID issued against the AppRole.

```shell
$ ./vault write -f auth/approle/role/my-role/secret-id
Key                   Value
---                   -----
secret_id             ae58d7d8-71e5-de73-28f6-9444c92423ff
secret_id_accessor    13f69811-451a-b1fd-e8dc-b80e2c6bf369
```

9. Write the RoleID and SecretID to files.

```shell
$ echo "0b876805-aa07-3406-453f-ff0d0721770b" > /tmp/test-vault-role-id
$ echo "ae58d7d8-71e5-de73-28f6-9444c92423ff" > /tmp/test-vault-secret-id
```

10. Disable secrets engines (this is because we are in development mode).

```shell
$ ./vault secrets disable kv
Success! Disabled the secrets engine (if it existed) at: kv/
$ ./vault secrets disable secret
Success! Disabled the secrets engine (if it existed) at: secret/
```

11. Enable the secret engine.

```shell
$ ./vault secrets enable -path=secret kv
Success! Enabled the kv secrets engine at: secret/
```

12. Write your credentials to Vault.

```shell
$ ./vault write secret/application/docker username=testuser password=testpassword
Success! Data written to: secret/application/docker
```

13. Check that the secret was successfully written.

```shell
$ ./vault read secret/application/docker
Key                 Value
---                 -----
refresh_interval    768h
password            testpassword
username            testuser
```

14. Give the newly-created AppRole permission to read this secret.

```shell
$ cat <<EOF > /tmp/policy.hcl
path "secret/application/docker" {
       capabilities = ["read", "list"]
}
EOF
$ ./vault policy write dev-policy /tmp/policy.hcl
Success! Uploaded policy: dev-policy
```

**Recap**
You now have a running Vault server and have stored your Docker credentials within it. You have also created an AppRole and given it permission to read the secret where the credentials are being kept.

### Try to pull the image in your local repository

```shell
$ docker pull localhost:5000/my-alpine
```

It should fail since you have not yet logged into the registry and the credentials are not stored in the `~/.docker/config.json` file. Now, we will set up the credential helper to automatically read the credentials from Vault and use them to login to your Docker registry the next time you run `docker pull localhost:5000/my-alpine`.

### Set up the credential helper

1. Install the `docker-credential-vault-login` binary (see the [Installation](#installation) section) and place it at some location on your `PATH`.

```shell
$ wget https://github.com/morningconsult/docker-credential-vault-login/releases/download/v0.2.10/docker-credential-vault-login_0.2.10_Linux_x86_64.tar.gz
$ tar xzf docker-credential-vault-login_0.2.10_Linux_x86_64.tar.gz
$ sudo mv docker-credential-vault-login /usr/local/bin
```

2. Create the configuration file.

```shell
$ sudo mkdir -p /etc/docker-credential-vault-login
$ cat <<EOF > /tmp/config.hcl
vault {
        address = "http://127.0.0.1:8200"
}

auto_auth {
        method "approle" {
                mount_path = "auth/approle"
                config     = {
                        role_id_file_path                   = "/tmp/test-vault-role-id"
                        secret_id_file_path                 = "/tmp/test-vault-secret-id"
                        remove_secret_id_file_after_reading = "false"
			secrets = {
				"localhost:5000" = "secret/application/docker"
			}
                }
        }

        sink "file" {
                config = {
                        path = "/tmp/token-sink"
                }
        }
}
EOF
$ sudo mv /tmp/config.hcl /etc/docker-credential-vault-login
```
3. Modify your `~/.docker/config.json` file to execute the credential helper when you run `docker pull`.

```shell
$ CONFIG=$( cat ~/.docker/config.json | jq -Mr '.credHelpers."localhost:5000" = "vault-login"' )
$ echo $CONFIG | jq -Mr > ~/.docker/config.json
```

4. Try to pull your image again.

```shell
$ docker pull localhost:5000/my-alpine
```

You should have successfully pulled the image from your local repository.

### Cleanup

1. Stop the registry container.

```shell
$ docker container stop registry
```

2. Prune Docker data and cleanup images.

```shell
$ docker system prune --volumes
$ docker image remove localhost:5000/my-alpine
$ docker image remove registry:2
```

3. Stop the Vault server (Ctrl+C).

4. Remove the saved authorization for your local registry and the credential helper from your `~/.docker/config.json` file.

```shell
$ CONFIG=$( cat ~/.docker/config.json | jq -Mr 'del(.credHelpers | ."localhost:5000") | del(.auths | ."localhost:5000")' )
$ echo $CONFIG | jq -Mr > ~/.docker/config.json
```
