# esecret

`esecret` is a utility for managing a collection of secrets in source control.

This tool is derived from [`ejson`](https://github.com/Shopify/ejson)

## Workflow

worflow mimics ejson workflow:

### 1: Create the Keydir

By default, EJSON looks for keys in `/opt/ejson/keys`. You can change this by
setting `EJSON_KEYDIR` or passing the `-keydir` option.

```
$ mkdir -p /opt/ejson/keys
```

### 2: Generate a keypair

When called with `-w`, `ejson keygen` will write the keypair into the `keydir`
and print the public key. Without `-w`, it will print both keys to stdout. This
is useful if you have to distribute the key to multiple servers via
configuration management, etc.

```
$ esecret keygen
Public Key:
63ccf05a9492e68e12eeb1c705888aebdcc0080af7e594fc402beb24cce9d14f
Private Key:
75b80b4a693156eb435f4ed2fe397e583f461f09fd99ec2bd1bdef0a56cf6e64
```

```
$ esecret keygen -w
53393332c6c7c474af603c078f5696c8fe16677a09a711bba299a6c1c1676a59
$ cat /opt/ejson/keys/5339*
888a4291bef9135729357b8c70e5a62b0bbe104a679d829cdbe56d46a4481aaf
```

### 3: Create an secrets file

The format is described in more detail [later on](#format). For now, create a
file that looks something like this. Fill in the `<key>` with whatever you got
back in step 2.

Create this file, for example, secrets.yml:

```yaml
#{{ public_key "<key>" }}
production:
  database_password: "{{ secret "1234password" }}"
```

### 4: Encrypt the file

Running `esecret encrypt secrets.yml` will encrypt any new plaintext keys in the
file, and leave any existing encrypted keys untouched:

```yaml
# {{ public_key "9332c940ec35ad08a6fc0d7286d19e3a01bfe33202f26df85e30a13fd828257b" }}
production:
  database_password: "{{ encrypted "EJ[1:a1wp3Oia0TrjJxi3AdoGSeOrtLKqEK1MqT2i2TgdXQI=:xr1tfOnKjjqdn/rloihdpzd8E9Uv1z7Y:dTJCMLBwUBxDovaFquT3XiifwiiWK4Qmg1F7/g==]" }}"
```

Try adding another plaintext secret to the file and run `esecret encrypt secrets.yml` again. The `database_password` field will not be changed, but the
new secret will be encrypted.

### 5: Decrypt the file

To decrypt the file, you must have a file present in the `keydir` whose name is
the 64-byte hex-encoded public key exactly as embedded in the `esecret` document.
The contents of that file must be the similarly-encoded private key. If you used
`esecret keygen -w`, you've already got this covered.

Unlike `esecret encrypt`, which overwrites the specified files, `esecret decrypt`
only takes one file parameter, and prints the output to `stdout`:

```
$ esecret decrypt secrets.yml
# {{ public_key "9332c940ec35ad08a6fc0d7286d19e3a01bfe33202f26df85e30a13fd828257b" }}
production:
  database_password: "{{ secret "1234password" }}"
```

For a deployment:
```
$ esecret decrypt secrets.yml --machine
# {{ public_key "9332c940ec35ad08a6fc0d7286d19e3a01bfe33202f26df85e30a13fd828257b" }}
production:
  database_password: "1234password"
```

## Format

The `esecret` document format is simple, but there are a few points to be aware
of:

1. Need ```{{ public_key "<key>" }}```
2. Known tags are ```public_key```, ```secret```, ```encrypted```
