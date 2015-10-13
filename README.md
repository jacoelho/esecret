# esecret

`esecret` is a utility for managing a collection of secrets in source control.

This tool is derived from `ejson`[https://github.com/Shopify/ejson]

## Workflow

worflow mimics ejson workflow:

### 1: Create the Keydir

By default, EJSON looks for keys in `/opt/ejson/keys`. You can change this by
setting `EJSON_KEYDIR` or passing the `-keydir` option.

```
$ mkdir -p /opt/ejson/keys
```
