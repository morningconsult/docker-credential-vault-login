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
                dh_type = "curve25519"
                dh_path = "/tmp/dh_pub.json"
		config = {
			path = "/tmp/foo"
                        // neither 'dh_priv ' nor 'dh_priv_env' is set
		}
	}
}
