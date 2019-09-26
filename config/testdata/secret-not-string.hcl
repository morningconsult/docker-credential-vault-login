auto_auth {
        method "aws" {
                mount_path = "auth/aws"
                config = {
                        role = "dev-role-iam",
                        type = "iam"
                        secret = 12345
                }
        }

        sink "file" {
                config = {
                        path = "/tmp/foo"
                }
        }
}