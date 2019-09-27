auto_auth {
	method "approle" {
		mount_path = "auth/approle"
		config     = {
			role_id_file_path   = "/tmp/role-id"
			secret_id_file_path = "/tmp/secret-id"
			secret              = "secret/docker/creds"
		}
	}

	sink "file" {
                wrap_ttl = "5m"
                aad_env_var = "TEST_AAD_ENV"
                dh_type = "curve25519"
                dh_path = "/tmp/file-foo-dhpath2"
                config = {
                        path = "/tmp/file-bar"
                }
        }

	sink "file" {
		config = {
			path = "/tmp/foo"
		}
	}
}
