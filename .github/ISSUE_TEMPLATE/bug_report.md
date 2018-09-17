---
name: Bug Report
about: You're experiencing an issue with this project that is different than the documented behavior.

---

When filing a bug, please include the following headings if possible. Any example text in this template can be deleted.

#### Overview of the Issue

A paragraph or two about the issue you're experiencing.

#### Reproduction Steps

Steps to reproduce this issue, eg:

1. Run `TARGET_GOOS=windows TARGET_GOARCH=amd64 make docker`
1. Move the binary to a location on your path
1. Run `docker pull`
1. View error

### A copy of your `config.json` file

Example:
```json
{
  "vault_auth_method": "ec2",
  "vault_role": "dev-role-ec2",
  "vault_secret_path": "secret/docker/creds"
}
```

### Operating system and Environment details

OS, Architecture, and any other information you can provide about the environment.

### Log Fragments

Include appropriate log fragments. 