package esecret

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/Shopify/ejson/crypto"
)

var (
	InvalidPublicKey = errors.New("invalid public key")
	InvalidSecret    = errors.New("invalid secret value")
	InvalidEncrypted = errors.New("invalid encrypted value")
)

type ctx struct {
	publicKey       string
	publicKeyBytes  [32]byte
	privateKeyBytes [32]byte
	removeTags      bool
}

func (c *ctx) LoadPublicKey(s string) error {
	v, err := extractPublicKey(s)
	if err != nil {
		return err
	}

	c.publicKey = s
	c.publicKeyBytes = v
	return nil
}

func (c *ctx) LoadPrivateKey(keydir string) error {
	privkey, err := findPrivateKey(c.publicKeyBytes, keydir)
	if err != nil {
		return err
	}

	c.privateKeyBytes = privkey
	return nil
}

func (c *ctx) Encrypt(value string) (string, error) {
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

func (c *ctx) Decrypt(value string) (string, error) {
	kp := crypto.Keypair{
		Public:  c.publicKeyBytes,
		Private: c.privateKeyBytes,
	}

	decrypter := kp.Decrypter()

	v, err := decrypter.Decrypt([]byte(value))
	if err != nil {
		return "", err
	}

	if c.removeTags {
		return string(v), nil
	}

	return fmt.Sprintf("{{ secret %s }}", string(v)), nil
}

func (c *ctx) public_key(item interface{}) (string, error) {
	switch item := item.(type) {
	case string:
		if err := c.LoadPublicKey(item); err != nil {
			return "", err
		}
		return fmt.Sprintf("{{ public_key %s }}", item), nil
	}
	return "", InvalidPublicKey
}

func (c *ctx) secret(item interface{}) (string, error) {
	var value string

	switch item := item.(type) {
	case int:
		value = strconv.Itoa(item)
	case string:
		value = item
	default:
		return "", InvalidSecret
	}

	enc, err := c.Encrypt(value)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("{{ encrypted %s }}", enc), nil
}

func (c *ctx) encrypted(item interface{}) (string, error) {
	var value string
	switch item := item.(type) {
	case int:
		value = strconv.Itoa(item)
	case string:
		value = item
	default:
		return "", InvalidEncrypted
	}

	dec, err := c.Decrypt(value)
	if err != nil {
		return "", err
	}

	if c.removeTags {
		return dec, nil
	}

	return fmt.Sprintf("{{ secret %s }}", dec), nil
}

func (c *ctx) newFuncMap() map[string]interface{} {
	fm := make(map[string]interface{})
	fm["public_key"] = c.public_key
	fm["secret"] = c.secret
	fm["encrypted"] = c.encrypted
	return fm
}
