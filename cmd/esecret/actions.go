package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/Shopify/ejson"
	"github.com/jacoelho/esecret"
)

func encryptAction(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("at least one file path must be given")
	}
	for _, filePath := range args {
		n, err := esecret.EncryptFileInPlace(filePath)
		if err != nil {
			return err
		}
		fmt.Printf("Wrote %d bytes to %s.\n", n, filePath)
	}
	return nil
}

func decryptAction(args []string, keydir, outFile string, machine bool) error {
	if len(args) != 1 {
		return fmt.Errorf("exactly one file path must be given")
	}
	decrypted, err := esecret.DecryptFile(args[0], keydir, machine)
	if err != nil {
		return err
	}

	target := os.Stdout
	if outFile != "" {
		target, err = os.Create(outFile)
		if err != nil {
			return err
		}
		defer func() { _ = target.Close() }()
	}
	fmt.Fprintln(target, decrypted)
	return nil
}

func keygenAction(args []string, keydir string, wFlag bool) error {
	pub, priv, err := ejson.GenerateKeypair()
	if err != nil {
		return err

	}

	if wFlag {
		keyFile := fmt.Sprintf("%s/%s", keydir, pub)
		err := writeFile(keyFile, []byte(priv), 0440)
		if err != nil {
			return err

		}
		fmt.Println(pub)

	} else {
		fmt.Printf("Public Key:\n%s\nPrivate Key:\n%s\n", pub, priv)

	}
	return nil

}

// for mocking in tests
var (
	writeFile = ioutil.WriteFile
)
