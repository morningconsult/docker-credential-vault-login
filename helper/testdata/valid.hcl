auto_auth {
  method "aws" {
    mount_path = "auth/aws"
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