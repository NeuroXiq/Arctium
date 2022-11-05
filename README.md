# Arctium - .NET Core Crypto Library
Arctium is a simple crypto library, created and maintained for learning purpose. 
It provides various cryptographic functions, ciphers, connection protocols etc. implemented for better or worse but probably they should works.

## Projects
Solution is partitioned into  a following projects, each of them is a set of related algorithms. If you wish to get more informations about specific project, algorithm and examples, see appropriate [docs] folder. Each folder contains more specific informations and examples.

### ArctiumCLI 
In the future there may be some console interface utility tool 

### Look up documents
This is a short summary of what is on the development stage and direct links 
for more interesting parts of the documentation.

## TLS 1.3
#### TLS 1.3 - Supported Features
|Name|Comment|
|:--:|:--:|
|Cipher suites|asdf|

#### TLS 1.3 - Basic Example
|Name|Link|Comment|
|:--:|:--:|:--:|
|Client - Basic connection|[Example Code][tls13-basic-example-client]|Connect to www.github.com|
|Server - Basic server|[Example Code][tls13-basic-example-server]|HTTP response for browser (e.g. Edge)|
|Client - ConnectionInfo|[Example Code][tls13-basic-example-client-connectioninfo]|Client - Show informations about established TLS 1.3 connection|
|Server - ConnectionInfo|[Example Code][tls13-basic-example-server-connectioninfo]|Server - Show informations about established TLS 1.3 connection|
|Client/Server - Close Connection|[Example Code][tls13-basic-example-closeconnection]|Closing TLS 1.3 connection|
|Setup server and connect client|[Example Code][tls13-basic-example-self-client-server]|Connect Arctium TLS 1.3 client to Arctium TLS 1.3 Server|


[tls13-basic-example-client]:<docs/lookup/basic-example-client.md>
[tls13-basic-example-server]:<docs/lookup/basic-example-server.md>
[tls13-basic-example-client-connectioninfo]:<docs/lookup/tls13-basic-example-client-connectioninfo.md>
[tls13-basic-example-server-connectioninfo]:<docs/lookup/tls13-basic-example-server-connectioninfo.md>
[tls13-basic-example-closeconnection]:<docs/lookup/tls13-basic-example-closeconnection.md>
[tls13-basic-example-self-client-server]:<docs/lookup/basic-example-self-client-server.md>

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
|Extension - Certificate Authorities|[Example Code][tls13-clientconfig-certauthorities]|How to configure certificate authorities|
|Extension - Pre Shared Key|[Example Code][tls13-clientconfig-presharedkey]|How to configure Pre Shared Key|
|Extension - GREASE|[Example Code][tls13-clientconfig-grease]|How to configure GREASE extension|


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
