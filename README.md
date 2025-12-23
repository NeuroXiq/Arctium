# Arctium - .NET Core Crypto Library
- - -
Download binaries archive: [Release-Link](https://github.com/NeuroXiq/Arctium/releases/tag/v0.0.0.9)

Nuget:
```
Install-Package Arctium.Shared
Install-Package Arctium.Cryptography
Install-Package Arctium.Standards
```
- - -
API Docs: \
https://dndocs.com/?packageName=Arctium.Shared&packageVersion=1.0.0.1 \
https://dndocs.com/?packageName=Arctium.Standards&packageVersion=1.0.0.1 \
https://dndocs.com/?packageName=Arctium.Cryptography&packageVersion=1.0.0.1 


Arctium is a simple crypto library, created and maintained for learning purpose. 
It provides various cryptographic functions, ciphers, connection protocols etc. implemented for better or worse but probably they should works.

## Projects
Solution is partitioned into  a following projects, each of them is a set of related algorithms. If you wish to get more informations about specific project, algorithm and examples, see appropriate [docs] folder. Each folder contains more specific informations and examples.

### ArctiumCLI 
In the future there may be some console interface utility tool 

### Look up documents
Following list shows all implemented features with links to examples

## Protocols

#### DNS
|Name|Documentation|Standard|
|DNS Client/Server: |[TODO]|[RFC-1034](https://datatracker.ietf.org/doc/html/rfc1034)|
|DNS Client/Server: |[TODO]|[RFC-1035](https://datatracker.ietf.org/doc/html/rfc1035)|
|DNS Client/Server: |[TODO]|[RFC-1183](https://datatracker.ietf.org/doc/html/rfc1183)|
|DNS Client/Server: |[TODO]|[RFC-1348](https://datatracker.ietf.org/doc/html/rfc1348)|
|DNS Client/Server: |[TODO]|[RFC-8020](https://datatracker.ietf.org/doc/html/rfc8020)|
|DNS Client/Server: |[TODO]|[RFC-8482](https://datatracker.ietf.org/doc/html/rfc8482)|
|DNS Client/Server: |[TODO]|[RFC-8767](https://datatracker.ietf.org/doc/html/rfc8767)|
|DNS Client/Server: |[TODO]|[RFC-9471](https://datatracker.ietf.org/doc/html/rfc9471)|
|DNS Client/Server: |[TODO]|[RFC-2308](https://datatracker.ietf.org/doc/html/rfc2308)|
|DNS Client/Server: |[TODO]|[RFC-2181](https://datatracker.ietf.org/doc/html/rfc2181)|
|DNS Client/Server: |[TODO]|[RFC-1982](https://datatracker.ietf.org/doc/html/rfc1982)|
|DNS Client/Server: |[TODO]|[RFC-1876](https://datatracker.ietf.org/doc/html/rfc1876)|
|DNS Client/Server: |[TODO]|[RFC-2065](https://datatracker.ietf.org/doc/html/rfc2065)|
|DNS Client/Server: |[TODO]|[RFC-4034](https://datatracker.ietf.org/doc/html/rfc4034)|
|DNS Client/Server: |[TODO]|[RFC-4035](https://datatracker.ietf.org/doc/html/rfc4035)|
|DNS Client/Server: |[TODO]|[RFC-4343](https://datatracker.ietf.org/doc/html/rfc4343)|
|DNS Client/Server: |[TODO]|[RFC-4592](https://datatracker.ietf.org/doc/html/rfc4592)|
|DNS Client/Server: |[TODO]|[RFC-2535](https://datatracker.ietf.org/doc/html/rfc2535)|
|DNS Client/Server: |[TODO]|[RFC-5936](https://datatracker.ietf.org/doc/html/rfc5936)|
|DNS Client/Server: |[TODO]|[RFC-4033](https://datatracker.ietf.org/doc/html/rfc4033)|



## TLS 1.3
#### TLS 1.3 - Supported Features
|Name|Supported|Comment|
|:--:|:--:|:----:|
|Cipher suites (RFC 8446)| TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256|Supported Cipher suites|
|Named Groups (RFC 8446)|Secp256r1, Secp384r1, Secp521r1, X25519, X448, Ffdhe2048, Ffdhe3072, Ffdhe4096, Ffdhe6144, Ffdhe8192|Supported Groups - Configurable on Client/Server (e.g. can only use X25519 and not any other)|
|NewSessionTicket (RFC 8446)|Yes|Client & Server (Client accept ticket and can use it, server generates ticket and send to client, both configurable)|
|Signature Schemes (RFC 8446)| EcdsaSecp256r1Sha256, EcdsaSecp384r1Sha384, EcdsaSecp521r1Sha512, RsaPssRsaeSha256, RsaPssRsaeSha384, RsaPssRsaeSha512|Signature generation & validation|
|Key Update (RFC 8446)|Yes|On Client & Server. At any time server or client can send key update any number of time. Keys are updated|
|Handshake Client Authentication|Yes|Client & Server - client can authenticate and server can request (configurable)|
|Post handhsake client authentication|Yes|Client & Server configurable. Client can authenticate multiple times server can request authentication at any time after handshake|
|Multiple server certificates|Yes|Server can have multiple certificates and select them based on client hello supported features|
|Extension - Server Name (RFC 6066)|Yes| |
|Extension - PskKeyExchangeMode (RFC 8446)|Yes|Must support because TLS 1.3 specs require it|
|Extension - Application Layer Protocol Negotiation (RFC-7301)|Yes|On client & server. Client can send any bytes (defined by IANA or arbitrary bytes) and server can accept/reject any ALPN or ignore this extension|
|Extension - Supported Version (RFC 8446)|Yes|Must be required by TLS 1.3 spec|
|Extension - Cookie (RFC 8446))|Yes|Required by TLS 1.3 spec|
|Extension - Signature Algorithms (RFC 8446)|Yes|Client & Server, configurable|
|Extension - KeyShare (RFC 8446)|Yes|Required by TLS 1.3 spec|
|Extension - SupportedGroups|Yes||
|Extension - MaxFragmentLength (RFC 6066)|Yes|Configurable on client & server|
|Extension - OidFilters|Yes|Can send this extension but only as raw bytes (so DER encoded from external source, Arctium lib can't encode to DER bytes for now)|
|Extension - Signature Algorithms Cert|Yes|Client & server can sent this extension|
|Extension - Certificate Authorities|Yes|Configurable|
|Extension - GREASE (RFC 9701)|Yes|Client & Server Configurable - can be enabled or disabled|

To use Arctium TLS 1.3 examples below following file with sample resources must be included. Examples base on it. If not included code will not compite and will need to be changed.

[Examples - Resources][tls13-examples-resources]

[tls13-examples-resources]:<docs/lookup/tls13-examples-resources.md>

#### TLS 1.3 - Basic Example
|Name|Link|Comment|
|:--:|:--:|:--:|
|Client - Basic connection|[Example Code][tls13-basic-example-client]|Connect to www.github.com|
|Server - Basic server|[Example Code][tls13-basic-example-server]|HTTP response for browser (e.g. Edge)|
|Client - ConnectionInfo|[Example Code][tls13-basic-example-client-connectioninfo]|Client - Show informations about established TLS 1.3 connection|
|Server - ConnectionInfo|[Example Code][tls13-basic-example-server-connectioninfo]|Server - Show informations about established TLS 1.3 connection|
|Client/Server - Close Connection|[Example Code][tls13-basic-example-closeconnection]|Closing TLS 1.3 connection|
|Setup server and connect client|[Example Code][tls13-basic-example-self-client-server]|Connect Arctium TLS 1.3 client to Arctium TLS 1.3 Server|
|Client/Server - Update Traffic Secret|[Example Code][tls13-basic-example-updatetrafficsecret]|Update Traffic Secret|
Key and Initialization Vector Update

[tls13-basic-example-client]:<docs/lookup/tls13-basic-example-client.md>
[tls13-basic-example-server]:<docs/lookup/tls13-basic-example-server.md>
[tls13-basic-example-client-connectioninfo]:<docs/lookup/tls13-basic-example-client-connectioninfo.md>
[tls13-basic-example-server-connectioninfo]:<docs/lookup/tls13-basic-example-server-connectioninfo.md>
[tls13-basic-example-closeconnection]:<docs/lookup/tls13-basic-example-closeconnection.md>
[tls13-basic-example-self-client-server]:<docs/lookup/tls13-basic-example-self-client-server.md>
[tls13-basic-example-updatetrafficsecret]:<docs/lookup/tls13-basic-example-updatetrafficsecret.md>

#### Arctium TLS 1.3 - Expected Usage Example
|Name|Link|Comment|
|:--:|:--:|:--:|
|Search Browser|[Example Code][tls13-client-github-search]|Very simple Console App for searching www.github.com and showing results|
|HTTP Server|[Example Code][tls13-server-webserver]|Very simple Console App HTTP server that handle multiple TLS 1.3 connections parallel|

[tls13-client-github-search]:<docs/lookup/tls13-client-github-search.md>
[tls13-server-webserver]:<docs/lookup/tls13-server-webserver.md>

#### Tls 1.3 - Server Configuration
|Name|Link|Comment|
|:--:|:--:|:--:|
|Cipher Suites|[Example Code][tls13-serverconfig-ciphersuites]|How to use specific cipher suites|
|Extension - Supported Groups|[Example Code][tls13-serverconfig-extension-supportedgroups]|How to allow specific groups to be used in key exchange|
|Extension - Signature Schemes|[Example Code][tls13-serverconfig-extension-signatureschemes]|How to allow specific signature schemes to be used in signature generation|
|Extension - Record Size Limit|[Example Code][tls13-serverconfig-extension-recordsizelimit]|How to configure Record size limit extension|
|Extension - ALPN|[Example Code][tls13-serverconfig-extension-alpn]|How to configure ALPN extension|
|Extension - Server Name|[Example Code][tls13-serverconfig-servername]|How to configure server name extension|
|Handshake Client Authentication|[Example Code][tls13-serverconfig-handshakeclientauth]|How to request client authentication during TLS 1.3 handshake|
|Extension - Oid Filters|[Example Code][tls13-serverconfig-extension-oidfilters]|How to configure Oid Filters extension|
|Extension - Post Handshake Client Authentication|[Example Code][tls13-serverconfig-posthandshakeclientauth]|How to configure post handshake client authentication and request client to authenticated at any time after after handshake completed|
|Extension - Certificate Authorities|[Example Code][tls13-serverconfig-extension-certauthorities]|How to configure certificate authorities extension|
|Extension - Pre Shared Key|[Example Code][tls13-serverconfig-presharedkey]|How to configure Pre shared key|
|Extension - GREASE|[Example Code][tls13-serverconfig-grease]|How to enable/disable GREASE extension|

[tls13-serverconfig-ciphersuites]:<docs/lookup/tls13-serverconfig-ciphersuites.md>
[tls13-serverconfig-extension-supportedgroups]:<docs/lookup/tls13-serverconfig-extension-supportedgroups.md>
[tls13-serverconfig-extension-signatureschemes]:<docs/lookup/tls13-serverconfig-extension-signatureschemes.md>
[tls13-serverconfig-extension-recordsizelimit]:<docs/lookup/tls13-serverconfig-extension-recordsizelimit.md>
[tls13-serverconfig-extension-alpn]:<docs/lookup/tls13-serverconfig-extension-alpn.md>
[tls13-serverconfig-servername]:<docs/lookup/tls13-serverconfig-servername.md>
[tls13-serverconfig-handshakeclientauth]:<docs/lookup/tls13-serverconfig-handshakeclientauth.md>
[tls13-serverconfig-extension-oidfilters]:<docs/lookup/tls13-serverconfig-extension-oidfilters.md>
[tls13-serverconfig-posthandshakeclientauth]:<docs/lookup/tls13-serverconfig-posthandshakeclientauth.md>
[tls13-serverconfig-extension-certauthorities]:<docs/lookup/tls13-serverconfig-extension-certauthorities.md>
[tls13-serverconfig-presharedkey]:<docs/lookup/tls13-serverconfig-presharedkey.md>
[tls13-serverconfig-grease]:<docs/lookup/tls13-serverconfig-grease.md>



#### Tls 1.3 - Client Configuration
|Name|Link|Comment|
|:--:|:--:|:--:|
|Cipher Suites|[Example Code][tls13-clientconfig-ciphersuites]|How to use specific cipher suites|
|Extension - Supported Groups|[Example Code][tls13-clientconfig-supportedgroups]|How to allow specific groups to be used in key exchange|
|Extension - Key share|[Example Code][tls13-clientconfig-keyshare]|How to precompute and sent specific groups in client hello in keyshare|
|Extension - Supported Signature Scheme|[Example Code][tls13-clientconfig-supportedsignatureschemes]|How to allow specific signature schemes to be used in signing operation|
|Extension - Record Size Limit|[Example Code][tls13-clientconfig-recordsizelimit]|How to configure Record size limit|
|Extension - ALPN|[Example Code][tls13-clientconfig-alpn]|How to configure ALPN (Application layer protocol negotiation)|
|Extension - Server Name|[Example Code][tls13-clientconfig-servername]|How to configure Server Name extension|
|Extension - Signature Algorithms Cert|[Example Code][tls13-clientconfig-signaturealgorithmscert]|How to configure Signature Algorithms Cert extension|
|Handshake Client Authentication|[Example Code][tls13-clientconfig-handshakeclientauth]|How to configure Handshake Client Authentication|
|Post Handshake Client Authentication|[Example Code][tls13-clientconfig-posthandshakeclientauth]|How to configure Post Handshake Client Authentication (server can request at any time, multiple times supported even with different client x509 certificates for each auth request)|
|Extension - Certificate Authorities|[Example Code][tls13-clientconfig-certauthorities]|How to configure certificate authorities|
|Extension - Pre Shared Key|[Example Code][tls13-clientconfig-presharedkey]|How to configure Pre Shared Key|
|Extension - GREASE|[Example Code][tls13-clientconfig-grease]|How to configure GREASE extension|

[tls13-clientconfig-ciphersuites]:<docs/lookup/tls13-clientconfig-ciphersuites.md>
[tls13-clientconfig-supportedgroups]:<docs/lookup/tls13-clientconfig-supportedgroups.md>
[tls13-clientconfig-keyshare]:<docs/lookup/tls13-clientconfig-keyshare.md>
[tls13-clientconfig-supportedsignatureschemes]:<docs/lookup/tls13-clientconfig-supportedsignatureschemes.md>
[tls13-clientconfig-recordsizelimit]:<docs/lookup/tls13-clientconfig-recordsizelimit.md>
[tls13-clientconfig-alpn]:<docs/lookup/tls13-clientconfig-alpn.md>
[tls13-clientconfig-servername]:<docs/lookup/tls13-clientconfig-servername.md>
[tls13-clientconfig-signaturealgorithmscert]:<docs/lookup/tls13-clientconfig-signaturealgorithmscert.md>
[tls13-clientconfig-handshakeclientauth]:<docs/lookup/tls13-clientconfig-handshakeclientauth.md>
[tls13-clientconfig-posthandshakeclientauth]:<docs/lookup/tls13-clientconfig-posthandshakeclientauth.md>
[tls13-clientconfig-certauthorities]:<docs/lookup/tls13-clientconfig-certauthorities.md>
[tls13-clientconfig-presharedkey]:<docs/lookup/tls13-clientconfig-presharedkey.md>
[tls13-clientconfig-grease]:<docs/lookup/tls13-clientconfig-grease.md>

## Elliptic Curves - SEC 2 / Verify Signature
|Name|Link|Comment|
|:--:|:--:|:--:|
|secp192k1 - Verify Signature|[Example Code][sec2-versign]|Verify ECC signature|
|secp192r1 - Verify Signature|[Example Code][sec2-versign]|Verify ECC signature|
|secp224k1 - Verify Signature|[Example Code][sec2-versign]|Verify ECC signature|
|secp224r1 - Verify Signature|[Example Code][sec2-versign]|Verify ECC signature|
|secp256k1 - Verify Signature|[Example Code][sec2-versign]|Verify ECC signature|
|secp256r1 - Verify Signature|[Example Code][sec2-versign]|Verify ECC signature|
|secp384r1 - Verify Signature|[Example Code][sec2-versign]|Verify ECC signature|
|secp521r1 - Verify Signature|[Example Code][sec2-versign]|Verify ECC signature|


[sec2-versign]:<docs/lookup/sec2-versign.md>


## Elliptic Curves - SEC 2 / Generate Signature
|Name|Link|Comment|
|:--:|:--:|:--:|
|secp192k1 - Signature|[Example Code][sec2-sign]|Generate ECC signature|
|secp192r1 - Signature|[Example Code][sec2-sign]|Generate ECC signature|
|secp224k1 - Signature|[Example Code][sec2-sign]|Generate ECC signature|
|secp224r1 - Signature|[Example Code][sec2-sign]|Generate ECC signature|
|secp256k1 - Signature|[Example Code][sec2-sign]|Generate ECC signature|
|secp256r1 - Signature|[Example Code][sec2-sign]|Generate ECC signature|
|secp384r1 - Signature|[Example Code][sec2-sign]|Generate ECC signature|
|secp521r1 - Signature|[Example Code][sec2-sign]|Generate ECC signature|

[sec2-sign]:<docs/lookup/sec2-sign.md>


## Elliptic Curves - SEC 2 / Key Exchange
|Name|Link|Comment|
|:--:|:--:|:--:|
|secp192k1|[Example Code][sec2-keyex]|Key Exchange example|
|secp192r1|[Example Code][sec2-keyex]|Key Exchange example|
|secp224k1|[Example Code][sec2-keyex]|Key Exchange example|
|secp224r1|[Example Code][sec2-keyex]|Key Exchange example|
|secp256k1|[Example Code][sec2-keyex]|Key Exchange example|
|secp256r1|[Example Code][sec2-keyex]|Key Exchange example|
|secp384r1|[Example Code][sec2-keyex]|Key Exchange example|
|secp521r1|[Example Code][sec2-keyex]|Key Exchange example|

[sec2-keyex]:<docs/lookup/sec2-keyex.md>

Arbitrary curve (not predefined, parameters must be provided):
[Arbitrary curve code examples][ecc-arbitrary]

[ecc-arbitrary]:<docs/lookup/sec2-keyex.md>

## Stream Ciphers
|Name|Link|Comment|
|:--:|:--:|:--:|
|CHACHA-20|[Code Example][strciph-chacha20]|ChaCha-20 Stream Cipher|
|Rabbit|[Code Example][strciph-rabbit]|Rabbit Stream Cipher|
|HC-256|[Code Example][strciph-hc256]|HC-256 Stream Cipher|

[strciph-chacha20]:<docs/lookup/strciph-chacha20.md>
[strciph-rabbit]:<docs/lookup/strciph-rabbit.md>
[strciph-hc256]:<docs/lookup/strciph-hc256.md>

## Block Ciphers
|Name|Link|Comment|
|:--:|:--:|:--:|
|AES-128|[Code Example][blockciph-aes128]|AES 128 Block Cipher|
|AES-192|[Code Example][blockciph-aes192]|AES 192 Block Cipher|
|AES-512|[Code Example][blockciph-aes256]|AES 256 Block Cipher|
|Camellia|[Code Example][blockciph-camellia]|Camellia Block cipher|
|Threefish-256|[Code Example][blockciph-threefish256]|Threefish 256 Block cipher|
|Threefish-512|[Code Example][blockciph-threefish512]|Threefish 512 Block cipher|
|Threefish-1024|[Code Example][blockciph-threefish1024]|Threefish 1024 Block cipher|
|Twofish|[Code Example][blockciph-twofish]|Twofish Block cipher|

[blockciph-aes128]:<docs/lookup/blockciph-aes128.md>
[blockciph-aes192]:<docs/lookup/blockciph-aes192.md>
[blockciph-aes256]:<docs/lookup/blockciph-aes256.md>
[blockciph-camellia]:<docs/lookup/blockciph-camellia.md>
[blockciph-threefish1024]:<docs/lookup/blockciph-threefish1024.md>
[blockciph-threefish256]:<docs/lookup/blockciph-threefish256.md>
[blockciph-threefish512]:<docs/lookup/blockciph-threefish512.md>
[blockciph-twofish]:<docs/lookup/blockciph-twofish.md>

## AEAD
|Name|Link|Comment|
|:--:|:--:|:--:|
|Poly1305-Chacha20|[Example Code][aead-poly1305chacha20]||
|Galois Counter Mode|[Example Code][aead-gcm]|GCM mode with custom tag length|
|CCM Mode|[Example Code][aead-ccm]|Dont use not work / TODO|

[aead-gcm]:<docs/lookup/aead-gcm.md>
[aead-ccm]:<docs/lookup/aead-ccm.md>
[aead-poly1305chacha20]:<docs/lookup/aead-poly1305.md>

## AEAD Predefined (RFC-5116)
|Name|Link|Comment|
|:--:|:--:|:--:|
|AEAD AES 128 CCM|[Example Code][rfc5116-aes128ccm]|Dont Use - Not working TODO/ Create AEAD Algorithm AES 128 CCM|
|AEAD AES 256 GCM|[Example Code][rfc5116-aes256gcm]|Create AEAD Algorithm AES 256 GCM|
|AEAD AES 256 CCM|[Example Code][rfc5116-aes256ccm]|Dont Use - Not working TODO / Create AEAD Algorithm AES 256 CCM|
|AEAD AES 128 CCM 8|[Example Code][rfc5116-aes128ccm8]|Create AEAD Algorithm AES 128 CCM 8|

[rfc5116-aes128ccm]:<docs/lookup/rfc5116-aes128ccm.md>
[rfc5116-aes256gcm]:<docs/lookup/rfc5116-aes256gcm.md>
[rfc5116-aes256ccm]:<docs/lookup/rfc5116-aes256ccm.md>
[rfc5116-aes128ccm8]:<docs/lookup/rfc5116-aes128ccm8.md>

## X25519 & X448 (RFC 7748)
|Name|Link|Comment|
|:--:|:--:|:--:|
|X25519 Curve|[Example Code][rfc7748-x25519]|Key Exchange using X25519 Curve|
|X448 Curve|[Example Code][rfc7748-x448]|Key Exchange using X448 Curve|

[rfc7748-x25519]:<docs/lookup/rfc7748-x25519.md>
[rfc7748-x448]:<docs/lookup/rfc7748-x448.md>

## PKCS#8
|Name|Link|Comment|
|:--:|:--:|:--:|
|PKCS#8 - Decode RSA private key from PKCS#8 file|[Example Code][pkcs8-rsa]|How to decode RSA Private key from PKCS#8 file|
|PKCS#8 - Decode ECC private key from PKCS#8 file|[Example Code][pkcs8-ecc]|How to decode ECC Private key from PKCS#8 file|

[pkcs8-rsa]:<docs/lookup/pkcs8-rsa.md>
[pkcs8-ecc]:<docs/lookup/pkcs8-ecc.md>

## FFDHE - RFC-7919
|Name|Link|Comment|
|:--:|:--:|:--:|
|FFDHE2048|[Example Code][ffdherfc7919]|Key Exchange using FFDHE2048|
|FFDHE3072|[Example Code][ffdherfc7919]|Key Exchange using FFDHE3072|
|FFDHE4096|[Example Code][ffdherfc7919]|Key Exchange using FFDHE4096|
|FFDHE6144|[Example Code][ffdherfc7919]|Key Exchange using FFDHE6144|
|FFDHE8192|[Example Code][ffdherfc7919]|Key Exchange using FFDHE8192|


[ffdherfc7919]:<docs/lookup/ffdherfc7919.md>
[ffdherfc7919]:<docs/lookup/ffdherfc7919.md>
[ffdherfc7919]:<docs/lookup/ffdherfc7919.md>
[ffdherfc7919]:<docs/lookup/ffdherfc7919.md>
[ffdherfc7919]:<docs/lookup/ffdherfc7919.md>

## PEM file decoding
|Name|Link|Comment|
|:--:|:--:|:--:|
|PEM - from file|[Example Code][pem-fromfile]|Decode PEM file from file on file system|
|PEM - from string|[Example Code][pem-fromstring]|Decode PEM file from string|

[pem-fromstring]:<docs/lookup/pem-fromstring.md>
[pem-fromfile]:<docs/lookup/pem-fromfile.md>

## Hash Functions
|Name|Link|Comment|
|:--:|:--:|:--:|
|BLAKE2b|[Example Code][hashfunc-generic]| Example of BLAKE2b|
|BLAKE2B_512|[Example Code][hashfunc-generic]| Example of BLAKE2B_512|
|Blake3|[Example Code][hashfunc-generic]| Example of Blake3|
|JH_224|[Example Code][hashfunc-generic]| Example of JH_224|
|JH_256|[Example Code][hashfunc-generic]| Example of JH_256|
|JH_384|[Example Code][hashfunc-generic]| Example of JH_384|
|JH_512|[Example Code][hashfunc-generic]| Example of JH_512|
|RadioGatun32|[Example Code][hashfunc-generic]| Example of RadioGatun32|
|RadioGatun64|[Example Code][hashfunc-generic]| Example of RadioGatun64|
|RIPEMD_160|[Example Code][hashfunc-generic]| Example of RIPEMD_160|
|SHA1|[Example Code][hashfunc-generic]| Example of SHA1|
|SHA2_224|[Example Code][hashfunc-generic]| Example of SHA2_224|
|SHA2_256|[Example Code][hashfunc-generic]| Example of SHA2_256|
|SHA2_384|[Example Code][hashfunc-generic]| Example of SHA2_384|
|SHA2_512|[Example Code][hashfunc-generic]| Example of SHA2_512|
|SHA3_224|[Example Code][hashfunc-generic]| Example of SHA3_224|
|SHA3_256|[Example Code][hashfunc-generic]| Example of SHA3_256|
|SHA3_384|[Example Code][hashfunc-generic]| Example of SHA3_384|
|SHA3_512|[Example Code][hashfunc-generic]| Example of SHA3_512|
|Skein_1024|[Example Code][hashfunc-generic]| Example of Skein_1024|
|Skein_256|[Example Code][hashfunc-generic]| Example of Skein_256|
|Skein_512|[Example Code][hashfunc-generic]| Example of Skein_512|
|Skein_VAR|[Example Code][hashfunc-generic]| Example of Skein_VAR|
|Streebog|[Example Code][hashfunc-generic]| Example of Streebog|
|Whirlpool|[Example Code][hashfunc-generic]| Example of Whirlpool|

[hashfunc-generic]:<docs/lookup/hashfunc-generic.md> 

## Hash - Related functions
|Name|Link|Comment|
|:--:|:--:|:--:|
|HKDF|[Example Code][hashrel-hkdf]|HKDF Examples|
|HMAC|[Example Code][hashrel-hmac]|HMAC Examples|
|Poly1305|[Example Code][hashrel-poly1305]|Poly1305 Examples|


[hashrel-hkdf]:<docs/lookup/hashrel-hkdf.md> 
[hashrel-hmac]:<docs/lookup/hashrel-hmac.md> 
[hashrel-poly1305]:<docs/lookup/hashrel-poly1305.md> 

## CRC
|Name|Link|Comment|
|:--:|:--:|:--:|
|CRC8_DVB_S2              |[Example Code][crc-examples]|Example of CRC8_DVB_S2              |
|CRC8_AUTOSAR|[Example Code][crc-examples]|Example of CRC8_AUTOSAR|
|CRC8_Bluetooth|[Example Code][crc-examples]|Example of CRC8_Bluetooth|
|CRC8_CDMA2000|[Example Code][crc-examples]|Example of CRC8_CDMA2000|
|CRC8_DARD|[Example Code][crc-examples]|Example of CRC8_DARD|
|CRC8_GSMA|[Example Code][crc-examples]|Example of CRC8_GSMA|
|CRC8_GSMB|[Example Code][crc-examples]|Example of CRC8_GSMB|
|CRC8_HITAG|[Example Code][crc-examples]|Example of CRC8_HITAG|
|CRC8_I_432_1|[Example Code][crc-examples]|Example of CRC8_I_432_1|
|CRC8_I_CODE|[Example Code][crc-examples]|Example of CRC8_I_CODE|
|CRC8_I_LTE|[Example Code][crc-examples]|Example of CRC8_I_LTE|
|CRC8_MAXIM_DOW|[Example Code][crc-examples]|Example of CRC8_MAXIM_DOW|
|CRC8_MIFARE_MAD|[Example Code][crc-examples]|Example of CRC8_MIFARE_MAD|
|CRC8_NRSC_5|[Example Code][crc-examples]|Example of CRC8_NRSC_5|
|CRC8_OPENSAFETY|[Example Code][crc-examples]|Example of CRC8_OPENSAFETY|
|CRC8_ROHC|[Example Code][crc-examples]|Example of CRC8_ROHC|
|CRC8SAE_J1850|[Example Code][crc-examples]|Example of CRC8SAE_J1850|
|CRC8SAE_SMBUS|[Example Code][crc-examples]|Example of CRC8SAE_SMBUS|
|CRC8SAE_TECH_3250|[Example Code][crc-examples]|Example of CRC8SAE_TECH_3250|
|CRC8SAE_WCDMA|[Example Code][crc-examples]|Example of CRC8SAE_WCDMA|
|CRC32_AIXM|[Example Code][crc-examples]|Example of CRC32_AIXM|
|CRC32_AUTOSAR|[Example Code][crc-examples]|Example of CRC32_AUTOSAR|
|CRC32_BASE91_D|[Example Code][crc-examples]|Example of CRC32_BASE91_D|
|CRC32_BZIP2|[Example Code][crc-examples]|Example of CRC32_BZIP2|
|CRC32_CD_ROM_EDC|[Example Code][crc-examples]|Example of CRC32_CD_ROM_EDC|
|CRC32_CKSUM|[Example Code][crc-examples]|Example of CRC32_CKSUM|
|CRC32_ISCSI|[Example Code][crc-examples]|Example of CRC32_ISCSI|
|CRC32_ISO_HDLC|[Example Code][crc-examples]|Example of CRC32_ISO_HDLC|
|CRC32_JAMCRC|[Example Code][crc-examples]|Example of CRC32_JAMCRC|
|CRC32_MEF|[Example Code][crc-examples]|Example of CRC32_MEF|
|CRC32_MPEG_2|[Example Code][crc-examples]|Example of CRC32_MPEG_2|
|CRC32_XFER|[Example Code][crc-examples]|Example of CRC32_XFER|
|CRC64_GO_ISO|[Example Code][crc-examples]|Example of CRC64_GO_ISO|
|CRC64_MS|[Example Code][crc-examples]|Example of CRC64_MS|
|CRC64_WE|[Example Code][crc-examples]|Example of CRC64_WE|
|CRC64_XZ|[Example Code][crc-examples]|Example of CRC64_XZ|
|CRC64_ECMA182|[Example Code][crc-examples]|Example of CRC64_ECMA182|


[crc-examples]:<docs/lookup/crc-examples.md> 

## Other
|Name|Link|Comment|
|:--:|:--:|:--:|
|CryptoAlgoFactory|[Example Code][other-cryptoalgofactory]|Crypto algo factory utility|
|X509 Certificate - Deserialize|[x509-deserialize]|Deserialize X509 Certificate From Bytes or from PEM file|
|X509 Certificate - RSA Public Key|[x509-geteccpubkey]|X509 Certificate - Get RSA public key from certificate|
|X509 Certificate - ECC Public Key|[x509-getrsapubkey]|X509 Certificate - Get ECC public key from certificate|
|X509 - DER Encode 'EcdsaSigValue' structure|[x509-encodeecdsasigvalue]|How to DER-Encode ECC signature to EcdsaSigValue structure|
|PKCS#1|[PKCS1v2_2]|Using PKCS#1 v2.2 API (RSASSA PSS) generate signature / verify signature etc.|

[other-cryptoalgofactory]:<docs/lookup/other-cryptoalgofactory.md>
[x509-deserialize]:<docs/lookup/x509-deserialize.md>
[x509-geteccpubkey]:<docs/lookup/x509-geteccpubkey.md>
[x509-getrsapubkey]:<docs/lookup/x509-getrsapubkey.md>
[x509-encodeecdsasigvalue]:<docs/lookup/x509-encodeecdsasigvalue.md>


|Name                       | Link              |
|:-------------------------:|:-----------------:|
|Camellia block cipher (128, 192, 256 key sizes)|    -        |
|Streebog-256|    -        |
|Streebog-512                  |    -        |
|CRC-8                  |    -        |
|CRC-16                  |    -        |
|CRC-32                  |    -        |
|RadioGatun-64                  |    -        |
|RadioGatun-32                  |    -        |
|Whirlpool                  |    -        |
|PKCS#1 v2.2 (RFC 8017)     |    [PKCS1v2_2]        |
|SHA1 (Hash function)       |    [SHA1]        |
|Skein (Hash function)      |    [Skein]        |
|BLAKE2b (Hash function)    |    [BLAKE2b]      |
|BLAKE3 (Hash function)     |    [BLAKE3]       |
|Twofish (Block cipher)     |     [Twofish]     |
|X509 V3 Certificate        | [X509Cert]        |
|Rabbit - stream cipher (ESTREAM)| [Rabbit]     |
|HC-256 - stream cipher (ESTREAM)| [HC256]      |
|Hash functions             | [HashFunctions]   |
|ASN.1 Standard             | [ASN1 Standard]   |
|ASN1. Simple Der decoder   | [Der decoder]     |
|TLS 1.2                    | [TLS12 Info]      |
|TLS 1.2 Examples           | [TLS12 examples]  |

[PKCS1v2_2]:<docs/lookup/pkcs1v2_2.md>
[SHA1]:<docs/lookup/sha1.md>
[JH]:<docs/lookup/jh.md>
[Skein]:<docs/lookup/skein.md>
[BLAKE2b]:<docs/lookup/blake2b.md>
[BLAKE3]:<docs/lookup/blake3.md>
[Twofish]:<docs/lookup/twofish.md>
[HC256]:<docs/lookup/hc-256.md>
[Rabbit]:<docs/lookup/rabbit.md>
[X509Cert]:<docs/lookup/x509-cert.md>
[HashFunctions]:<docs/Cryptography/HashFunctions/>
[TLS12 Info]:<docs/Connection/Tls/readme.md>
[TLS12 examples]:<docs/Connection/Tls/examples.md>
[Der decoder]:<./docs/lookup/asn1-x690-decoder.md>


### Overview of root dirs of documentation

|Project      |          Documentation|
|:-----------:|:---------------------:|
|Connection   |[Connection docs]      |
|Cryptography |[Cryptography docs]    |
|Encoding     |[Encoding docs]        |

[docs]:<docs/>
[Connection docs]:<docs/Connection>
[Cryptography docs]:<docs/Cryptography>
[Encoding docs]:<docs/Encoding>
