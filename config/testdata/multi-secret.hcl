auto_auth {
	method "approle" {
		mount_path = "auth/approle"
		config = {
			role_id_file_path   = "/tmp/role-id"
			secret_id_file_path = "/tmp/secret-id"
			secret = {
				registry-1.example.com = "secret/docker/creds"
				registry-2.example.com = "secret/docker/extra/creds"
			}
		}
	}

	sink "file" {
		config = {
			path = "/tmp/foo"
		}
	}
}
