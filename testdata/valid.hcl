auto_auth {
	method "approle" {
		mount_path = "auth/approle"
		config = {
			role_id_file_path   = "/tmp/role-id"
			secret_id_file_path = "/tmp/secret-id"
			secret              = "secret/docker/creds"
		}
	}

	sink "file" {
		config = {
			path = "/tmp/foo"
		}
	}
}