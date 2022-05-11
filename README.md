# RSA private key encryption and public key decryption in Golang

The common method to encrypt and decrypt data with [RSA cryptographic keys](<https://en.wikipedia.org/wiki/RSA_(cryptosystem)>) is to encode data with public key and to decode it with private key.

But sometimes some APIs demand to use RSA-cryptography in an opposite way.  
You need to **encode data with private key**.  
And **decode data with public key**.

Examples of such APIs:

- [Chef API](https://docs.chef.io/server/api_chef_server/#canonical-header-format-10-using-sha-1)
- [Tribe Payments API](https://doc.tribepayments.com/trb-isac-acquirer-mapi-api/1.0/#appendix--security--cryptography)

Here is the specs of such operations at [openssl.org](https://www.openssl.org/docs/man1.1.1/man3/RSA_public_decrypt.html).

And languages like Node.js or PHP have appropriate methods for this "out of the box".

- [Node.js crypto.privateEncrypt](https://nodejs.org/api/crypto.html#cryptoprivateencryptprivatekey-buffer)
- [Node.js crypto.publicDecrypt](https://nodejs.org/api/crypto.html#cryptopublicdecryptkey-buffer)
- [PHP openssl_private_encrypt](https://www.php.net/manual/ru/function.openssl-private-encrypt.php)
- [PHP openssl_public_decrypt](https://www.php.net/manual/ru/function.openssl-public-decrypt.php)

But the native [Golang RSA package](https://pkg.go.dev/crypto/rsa) does not have methods for such crypto ops.

I spent some time trying to understand how to use private-to-public cryptography with Golang.  
Here is the solution with three notes you need to understand.

## First

You can use this to encode-decode only small pieces of data. Like session keys or something.  
Trying to encode long data will cause `crypto/rsa: message too long for RSA public key size` error while encrypting.

## Second: encrypt using private key

In Go we are using [rsa.SignPKCS1v15](https://pkg.go.dev/crypto/rsa#SignPKCS1v15) to encrypt.  
The actual operation in terms of cryptography is signing.  
But we are using it with `crypto.Hash(0)` attribute.  
As a result we'll get a fully encrypted string.

Citation from the rsa package:  
_Note that hashed must be the result of hashing the input message using the given hash function.  
If hash is zero, hashed is signed directly.
This isn't advisable except for interoperability._

## Third: decrypt using public key

This is an operation you can't do in Golang using the standard RSA package.  
But it's easy to realize the logic by yourself. Look at the code.

# How to generate keys using openssl linux utility

1. Create key pair  
   `openssl genrsa -out keypair.pem 2048`

1. Extract public part  
   `openssl rsa -in keypair.pem -pubout -out public.key`

1. Extract private part in PKCS#8 syntax  
   `openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in keypair.pem -out pkcs8.key`
