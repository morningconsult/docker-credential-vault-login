auto_auth {
  method "aws" {
    config = {
      role = "dev-role-iam",
      type = "iam"
      secret = "secret/docker/creds"
    }
  }

  sink "file" {
    config = {
      path = "/tmp/foo"
    }
  }
}