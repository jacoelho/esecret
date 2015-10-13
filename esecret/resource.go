package esecret

import (
	"github.com/Shopify/ejson/crypto"
)

type ctx struct {
	publicKey       string
	publicKeyBytes  [32]byte
	privateKeyBytes [32]byte
	removeTags      bool
}

func (c *ctx) loadPublicKey(s string) error {
	v, err := extractPublicKey(s)
	if err != nil {
		return err
	}

	c.publicKey = s
	c.publicKeyBytes = v
	return nil
}

func (c *ctx) loadPrivateKey(keydir string) error {
	privkey, err := findPrivateKey(c.publicKeyBytes, keydir)
	if err != nil {
		return err
	}

	c.privateKeyBytes = privkey
	return nil
}

func (c *ctx) encrypt(value string) (string, error) {
	var kp crypto.Keypair

	if err := kp.Generate(); err != nil {
		return "", err
	}

	encrypter := kp.Encrypter(c.publicKeyBytes)

	v, err := encrypter.Encrypt([]byte(value))
	if err != nil {
		return "", err
	}

	return string(v), nil
}

func (c *ctx) decrypt(value string) (string, error) {
	kp := crypto.Keypair{
		Public:  c.publicKeyBytes,
		Private: c.privateKeyBytes,
	}

	decrypter := kp.Decrypter()

	v, err := decrypter.Decrypt([]byte(value))
	if err != nil {
		return "", err
	}

	return string(v), nil
}
