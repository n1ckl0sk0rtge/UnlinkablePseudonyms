# (Un)linkanle Pseudonyms

This library contains the functionality of unlinkable pseudonyms based on RSA.

## How to use

```
Base64.Encoder b64Enc = Base64.getEncoder();

String input = "testIdentifier";

// Converter
KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
keyPairGen.initialize(1024);
KeyPair prfPair = keyPairGen.generateKeyPair();

PRFSecretExponent xa = new PRFSecretExponent(256, (RSAPrivateCrtKey) prfPair.getPrivate());
byte[] pseuA = Pseudonym.generate(input.getBytes(), xa, (RSAPublicKey) prfPair.getPublic());
PRFSecretExponent xb = new PRFSecretExponent(256, (RSAPrivateCrtKey) prfPair.getPrivate());
byte[] pseuB = Pseudonym.generate(input.getBytes(), xb, (RSAPublicKey) prfPair.getPublic());

// Server A
System.out.println(b64Enc.encodeToString(pseuA));

// Server B
System.out.println(b64Enc.encodeToString(pseuB));

// Converter
byte[] pseuAinB = Pseudonym.convert(pseuA, xa, xb, (RSAPrivateCrtKey) prfPair.getPrivate());

// Server B
System.out.println(b64Enc.encodeToString(pseuAinB));
```

## Implementation References

* [Lehmann, Camenisch - Privacy for Distributed Databases via (Un)linkable Pseudonyms](https://eprint.iacr.org/2017/022.pdf)
* [CL15 Anonymous ID Mapping](https://asecuritysite.com/homomorphic/cl15)