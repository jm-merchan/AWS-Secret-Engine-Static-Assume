pid_file = "/tmp/vault-agent.pid"
auto_auth {
    method "approle" {
        mount_path = "auth/approle"
        config = {
            role_id_file_path = "/tmp/approle-role-id"
            secret_id_file_path = "/tmp/approle-secret-id"
        }
    }
    sink "file" {
        config = {
            path = "/tmp/agent-token"
        }
    }
}

# Render KVv2 secret to a file
template {
    contents = <<TMPL
        {{- with secret "secretv2/data/app-test" }}
        username={{ .Data.data.username }}
        password={{ .Data.data.password }}
        {{- end }}
TMPL
    destination = "/tmp/app-test-secret.env"
    perms        = "0640"
}

# Render AWS static credentials to a file
template {
    contents = <<TMPL
    {{- with secret "aws/static-creds/app-test" }}
    AWS_ACCESS_KEY_ID={{ .Data.access_key }}
    AWS_SECRET_ACCESS_KEY={{ .Data.secret_key }}
    {{- end }}
TMPL
    destination = "/tmp/app-test-aws.env"
    perms        = "0640"
}

