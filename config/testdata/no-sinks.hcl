cache {
  use_auto_auth_token = true
}
listener "unix" {
	address = "/tmp/dcvl-agent"
}
auto_auth {
	method "approle" {
		mount_path = "auth/approle"
		config = {
			role_id_file_path   = "/tmp/role-id"
			secret_id_file_path = "/tmp/secret-id"
			secret              = "secret/docker/creds"
		}
	}
}
