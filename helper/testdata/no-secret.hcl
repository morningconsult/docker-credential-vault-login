auto_auth {
  method "aws" {
    mount_path = "auth/aws"
    config = {
      role = "dev-role-iam",
      type = "iam"
    }
  }

  sink "file" {
    config = {
      path = "/tmp/foo"
    }
  }
}