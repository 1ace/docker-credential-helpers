package main

import (
  "github.com/docker/docker-credential-helpers/credentials"
  "github.com/docker/docker-credential-helpers/lastpass"
)

func main() {
  credentials.Serve(lastpass.LastPass{})
}
