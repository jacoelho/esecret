package esecret

import (
	"errors"
	"fmt"
	"strconv"
)

var (
	InvalidPublicKey = errors.New("invalid public key")
	InvalidSecret    = errors.New("invalid secret value")
	InvalidEncrypted = errors.New("invalid encrypted value")
)

func (c *ctx) public_key(item interface{}) (string, error) {
	switch item := item.(type) {
	case string:
		if err := c.loadPublicKey(item); err != nil {
			return "", err
		}
		return fmt.Sprintf("{{ public_key \"%s\" }}", item), nil
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

	enc, err := c.encrypt(value)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("{{ encrypted \"%s\" }}", enc), nil
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

	dec, err := c.decrypt(value)
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
