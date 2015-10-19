package main

import (
	"fmt"
	"os"

	"github.com/codegangsta/cli"
)

const (
	Version = "0.0.1"
)

func main() {
	app := cli.NewApp()
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "keydir, k",
			Value:  "/opt/ejson/keys",
			Usage:  "Directory containing EJSON keys",
			EnvVar: "EJSON_KEYDIR",
		},
	}

	app.Usage = "manage encrypted secrets using public key encryption"
	app.Version = Version
	app.Author = "Burke Libbey/José Coelho"
	app.Email = "burke.libbey@shopify.com/jose.coelho@linkedcare.com"
	app.Commands = []cli.Command{
		{
			Name:      "encrypt",
			ShortName: "e",
			Usage:     "(re-)encrypt one or more files",
			Action: func(c *cli.Context) {
				if err := encryptAction(c.Args()); err != nil {
					fmt.Println("Encryption failed:", err)
					os.Exit(1)
				}
			},
		},
		{
			Name:      "decrypt",
			ShortName: "d",
			Usage:     "decrypt an encrypted file",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "o",
					Usage: "print output to the provided file, rather than stdout",
				},
				cli.StringFlag{
					Name:  "private-key",
					Usage: "private key to use",
				},
				cli.BoolFlag{
					Name:  "machine",
					Usage: "output without esecret tags",
				},
			},
			Action: func(c *cli.Context) {
				if err := decryptAction(c.Args(), c.GlobalString("keydir"), c.String("o"), c.String("private-key"), c.Bool("machine")); err != nil {
					fmt.Println("Decryption failed:", err)
					os.Exit(1)
				}
			},
		},
		{
			Name:      "keygen",
			ShortName: "g",
			Usage:     "generate a new keypair",
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "write, w",
					Usage: "rather than printing both keys, print the public and write the private into the keydir",
				},
			},
			Action: func(c *cli.Context) {
				if err := keygenAction(c.Args(), c.GlobalString("keydir"), c.Bool("write")); err != nil {
					fmt.Println("Key generation failed:", err)
					os.Exit(1)
				}
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Println("Unexpected failure:", err)
		os.Exit(1)
	}
}
