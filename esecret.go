package esecret

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"text/template"

	"github.com/Shopify/ejson/crypto"
)

func ExtractPublicKey(s string) ([32]byte, error) {
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

func TemplateRecover() {
	if r := recover(); r != nil {
		fmt.Println("error parsing file")
	}
}

func EncryptFileInPlace(filePath string) (int, error) {
	data, err := readFile(filePath)
	if err != nil {
		return -1, err
	}

	fileMode, err := getMode(filePath)
	if err != nil {
		return -1, err
	}

	var myKP crypto.Keypair
	if err := myKP.Generate(); err != nil {
		return -1, err
	}

	var pubkey [32]byte
	var encrypter *crypto.Encrypter
	fm := template.FuncMap{
		"public_key": func(public string) string {
			pubkey, err = ExtractPublicKey(public)
			if err != nil {
				return err.Error()
			}
			encrypter = myKP.Encrypter(pubkey)
			return fmt.Sprintf("{{ public_key \"%s\" }}", public)
		},
		"secret": func(secret string) string {
			v, err := encrypter.Encrypt([]byte(secret))
			if err != nil {
				panic(err)
			}
			return fmt.Sprintf("{{ encrypted \"%s\" }}", string(v))
		},
	}

	defer TemplateRecover()
	tmpl, err := template.New("esecret").Funcs(fm).Parse(string(data))
	if err != nil {
		return -1, err
	}

	var newData bytes.Buffer
	if err = tmpl.Execute(&newData, nil); err != nil {
		return -1, err
	}

	if err := writeFile(filePath, newData.Bytes(), fileMode); err != nil {
		return -1, err
	}

	return len(newData.Bytes()), nil
}

func DecryptFile(filePath, keydir string, machine bool) (string, error) {

	data, err := readFile(filePath)
	if err != nil {
		return "", err
	}

	var pubkey [32]byte
	var decrypter *crypto.Decrypter
	fm := template.FuncMap{
		"public_key": func(public string) string {
			pubkey, err = ExtractPublicKey(public)
			if err != nil {
				return err.Error()
			}
			privkey, err := findPrivateKey(pubkey, keydir)
			if err != nil {
				panic("private key not found")
			}
			myKP := crypto.Keypair{
				Public:  pubkey,
				Private: privkey,
			}
			decrypter = myKP.Decrypter()

			return fmt.Sprintf("{{ public_key \"%s\" }}", public)
		},
		"encrypted": func(secret string) string {
			if decrypter != nil {
				v, err := decrypter.Decrypt([]byte(secret))
				if err != nil {
					panic(err)
				}

				if machine {
					return fmt.Sprintf("\"%s\"", string(v))
				}
				return fmt.Sprintf("{{ secret \"%s\" }}", string(v))

			} else {
				return ""
			}
		},
	}

	defer TemplateRecover()
	tmpl, err := template.New("esecret").Funcs(fm).Parse(string(data))
	if err != nil {
		return "", err
	}

	var newData bytes.Buffer
	if err = tmpl.Execute(&newData, nil); err != nil {
		return "", err
	}

	return newData.String(), nil
}

func findPrivateKey(pubkey [32]byte, keydir string) (privkey [32]byte, err error) {
	keyFile := fmt.Sprintf("%s/%x", keydir, pubkey)
	var fileContents []byte
	fileContents, err = readFile(keyFile)
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

// for mocking in tests
func _getMode(path string) (os.FileMode, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return fi.Mode(), nil
}

// for mocking in tests
var (
	readFile  = ioutil.ReadFile
	writeFile = ioutil.WriteFile
	getMode   = _getMode
)
