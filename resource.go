package esecret

import (
	"github.com/Shopify/ejson/crypto"
)

type ctx struct {
	publicKey        string
	publicKeyBytes   [32]byte
	privateKeyLoaded bool
	privateKey       string
	privateKeyBytes  [32]byte
	keydir           string
	removeTags       bool
	decryptFile      bool
	file             FileInterface
}

type ctxConfig struct {
	keydir     string
	privateKey string
	decrypt    bool
	removeTags bool
}

func newCtx(config ctxConfig) *ctx {
	return &ctx{
		keydir:      config.keydir,
		privateKey:  config.privateKey,
		decryptFile: config.decrypt,
		removeTags:  config.removeTags,
		file:        &file{},
	}
}

func (c *ctx) loadPublicKey(s string) error {
	v, err := extractKey(s)
	if err != nil {
		return err
	}

	c.publicKey = s
	c.publicKeyBytes = v
	return nil
}

func (c *ctx) loadPrivateKey() error {
	if c.privateKeyLoaded {
		return nil
	}

	if len(c.privateKey) == 0 {
		privkey, err := c.file.ReadPrivateKey(c.keydir, c.publicKey)
		if err != nil {
			return err
		}
		v, err := extractKey(privkey)
		if err != nil {
			return err
		}
		c.privateKeyLoaded = true
		c.privateKeyBytes = v
		return nil
	}

	v, err := extractKey(c.privateKey)
	if err != nil {
		return err
	}

	c.privateKeyLoaded = true
	c.privateKeyBytes = v
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
