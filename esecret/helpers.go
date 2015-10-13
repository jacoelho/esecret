package esecret

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
)

func extractPublicKey(s string) ([32]byte, error) {
	var key [32]byte

	if len(s) != 64 {
		return key, errors.New("invalid key string")
	}

	bs, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return key, err
	}

	if len(bs) != 32 {
		return key, errors.New("invalid key decoded")
	}

	copy(key[:], bs)
	return key, nil
}

func findPrivateKey(pubkey [32]byte, keydir string) (privkey [32]byte, err error) {
	keyFile := fmt.Sprintf("%s/%x", keydir, pubkey)
	var fileContents []byte
	fileContents, err = ioutil.ReadFile(keyFile)
	if err != nil {
		err = fmt.Errorf("couldn't read key file (%s)", err.Error())
		return
	}

	bs, err := hex.DecodeString(strings.TrimSpace(string(fileContents)))
	if err != nil {
		return
	}

	if len(bs) != 32 {
		err = fmt.Errorf("invalid private key retrieved from keydir")
		return
	}

	copy(privkey[:], bs)
	return
}
