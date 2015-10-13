package esecret

import (
	"fmt"
	"io/ioutil"
)

type FileInterface interface {
	ReadFile(path string) (string, error)
	WriteFile(path string)
	ReadPrivateKey(keydir, pubkey string) (string, error)
}

type file struct{}

func (f *file) ReadFile(path string) (string, error) {
	var fileContents []byte

	fileContents, err := ioutil.ReadFile(path)
	if err != nil {
		return "", err
	}

	return string(fileContents), nil
}

func (f *file) ReadPrivateKey(keydir, pubkey string) (string, error) {
	// TODO path os aware
	keyFile := fmt.Sprintf("%s/%s", keydir, pubkey)

	k, err := f.ReadFile(keyFile)
	if err != nil {
		return "", err
	}
	return k, nil
}

func (f *file) WriteFile(path string) {
	//
}
