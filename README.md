# Altinn Securify

> NOTE! This is work-in-progress PoC, and not released/supported in any way at this time

The transformer is a Maskinporten-secured REST API that allows authorized parties to create secure (encrypted) representations of any plaintext small string (<2KB), and control which parties are allowed to decrypt it using the same API.

The principal application is transferring sensitive data (session information, personal identifiers, etc.) in URLs as query params, where the data must be protected from tampering and unauthorized access and storage in eg. access logs.

## Local installation

1. Clone the repo
2. Navigate to the project directory
3. Set up an encryption key: `dotnet user-secrets set "TransformerConfig:EncryptionKeys" "20250102:$(head -c 32 /dev/urandom | base64)"`
4. Run the application (`dotnet run`)

See `altinn-securify.http` for an example request

## Quickstart

### Encrypting data

```http
POST /api/v1/encrypt
{
    "plaintext": "somesecretvalue", // or any arbitrary valid JSON
    "settings": { // all are optional
        "expires": "2024-12-18T23:00:00Z", // default 1 minute (max 20 minutes)
        "requireOrgNo": ["991825827"], // default any org number
        "requireClientId": ["042fbe5d-bbfb-41cf-bada-9b9b52073a9b"], // default any client id
        "requireScope": ["some:arbitrary-scope"] // default no additional scope (besides altinn:securify)
    }
}
```
Response:
```http
{
    "ciphertext": "as_2ZXJzaW9uIjoxLCJrZXlJRCI6IjIwMjUwMTAyOjJkZjM..."
}
```

### Decrypting data

```http
POST /api/v1/decrypt
{
    "ciphertext": "as_2ZXJzaW9uIjoxLCJrZXlJRCI6IjIwMjUwMTAyOjJkZjM..."
}
```
Reponse:
```jsonc
{
  "at": "2025-03-30T23:42:55.206517+02:00",
  "by": {
    "orgNo": "991825827",
    "clientId": "cf991714-976c-47eb-88c6-dbbc7f65832d",
    "scopes": [
      "altinn:securify"
    ]
  },
  "plaintext": "somesecretvalue"
}
```

## How it works

When requesting encryption of any arbitrary data, the returned string will be Base64URL encoded, which ensures that it can be safely used as query strings in URLs.

The encrypted data is *not* designed to be persisted, but must be exchanged to its plain text variant before it is stored. Any requirement for securing of this data at-rest is out of scope for this solution.

The encryption used is AES-GCM, which includes nonces and authentication tags to ensure that a given plaintext will not produce the same ciphertext twice, and to detect tampering. A version identifier is also prepended for future-proofing, allowing for multiple encryption algorithms to be supported in the future.

Along the nonce and authentication tag, a key ID is also embedded. This allows for runtime key resolution when decrypting, allowing for key server side rotation and revocation. 

**The entire output value (when encrypting) should be considered opaque by consumers**, and should not be parsed or assumed having any particular form (besides being URL safe). This allows the API to change encodings, encryption algorithms, modes, key/nonce/tag sizes on a per version or even per key-ID basis. This means no key material should be handled by consumers, and no assumptions should be made about the output format (other than being URL safe).

## Security settings

When encrypting data, additional metadata can be supplied that adds restrictions to consumers wanting to exchange the encrypted data back to its plain text representations. If any of the restrictions is not met, the API will refuse to return the decrypted plaintext and will instead produce an error.

By default, no restrictions are added except for a expiry time, which is capped at 20 minutes. This is to discourage persisting secured-data, which will potentially break as keys will be rotated.

| Restriction | Description |
|-------------|-------------|
| `expires` | UTC timestamp after which the secured data can no longer be decrypted |
| `requireOrgNo` | Array of norwegian organization numbers. The consumer claim of the Maskinporten-token provided must match one of the supplied organization numbers. |
| `requireClientId` | Array of client ids (strings, usually UUIDs). The client_id claim of the Maskinporten-token provided must match one of the supplied client ids. |
| `requireScope` | Array of scopes (strings). The scope claim of the Maskinporten-token must contain at least one of the supplied scopes. |

## Maskinporten

The API is secured using [Maskinporten](https://docs.digdir.no/docs/Maskinporten/maskinporten_summary), which is a OAuth2-based authorization server that allows for fine-grained access control to APIs. In order to use the API, a Maskinporten token needs be supplied in the `Authorization` header, having the scope `altinn:securify`. 

## TODO

* Deployment (authorization cluster?)
