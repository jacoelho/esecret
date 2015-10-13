package esecret

import (
  "fmt"
  "errors"
  "strconv"

	"github.com/Shopify/ejson/crypto"
)

var (
  InvalidPublicKey = errors.New("invalid public key")
  InvalidSecret = errors.New("invalid secret value")
  InvalidEncrypted = errors.New("invalid encrypted value")
)

type ctx struct {
  publicKey string
  publicKeyBytes [32]byte
  privateKeyBytes [32]byte
  removeTags bool
}

func (c *ctx) SetPublicKey(s string) error {
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

return fmt.Sprintf("{{ encrypted %s }}", string(v)), nil
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
  case int:
    return strconv.Itoa(item), nil
  case string:
    return item, nil
  }
  return "", InvalidPublicKey
}

func (c *ctx) secret(item interface{}) (string, error) {
  c.publicKey = "foobar"
  switch item := item.(type) {
  case int:
    return strconv.Itoa(item), nil
  case string:
    return item, nil
  }
  return "", InvalidSecret
}

func (c *ctx) encrypted(item interface{}) (string, error) {
  switch item := item.(type) {
  case int:
    return strconv.Itoa(item), nil
  case string:
    //return item, nil
    return c.publicKey, nil
  }
  return "", InvalidEncrypted
}

func (c *ctx) newFuncMap() map[string]interface{} {
  fm := make(map[string]interface{})
  fm["public_key"] = c.public_key
  fm["secret"] = c.secret
  fm["encrypted"] = c.encrypted
  return fm
}
