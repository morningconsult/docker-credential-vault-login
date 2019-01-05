auto_auth {
  method "aws" {
    mount_path = "auth/aws"
    config = {
      role = "dev-role-iam",
      type = "ec2"
      secret = "secret/docker/creds"
    }
  }

  sink "file" {
    config = {
      path = "/tmp/foo"
    }
  }
}