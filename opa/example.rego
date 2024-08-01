package example.authz

default allow = false

allow {
  input.user == "testuser"
  input.action == "read"
  input.resource == "protected"
}

