package testdata

import (
	_ "embed"
)

var (
	//go:embed public_key.pem
	PublicKeyPEM string
	//go:embed private_key.pem
	PrivateKeyPEM string
)
