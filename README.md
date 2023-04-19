# chromatic-signed-webhook-examples

These are example implementations of validating the `X-Webhook-Signature` header from Chromatic.

Each is organized under the language used, and attempts to use common packages to give a complete example.

![Demo of NodeJS example](demo.gif)

# How This Header Works

To authenticate webhooks, Chromatic will send a special header containing a signed JWT.

The payload of this JWT includes the following:

```
{
  "iss": "chromatic",      // always 'chromatic'
  "iat": 1638988199,       // unix timestamp that this JWT was issued
  "sha256": "e4cb...b958", // hex encoded SHA256 digest of the POST body
}
```

This JWT will always be `HS256`, and use the secret key you coordinate with Chromatic support.

## Verification

  1. Check for, and retrieve the `X-Webhook-Signature` header value
  1. Decode this JWT using the secret key
  1. Check that `iat` is recent (as determined by your threat model)
  1. Read the POST body, and generate a SHA256 hex digest
  1. Compare that to the `sha256` field

# The /request Tool

This is a CLI tool written in Go which is capable of making signed requests in the same manner as Chromatic.

By default, you can use it against your example servers with no flags, as the defaults are shared across all example servers.

