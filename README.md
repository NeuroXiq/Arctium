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



|Name                       | Link              |
|:-------------------------:|:-----------------:|
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
