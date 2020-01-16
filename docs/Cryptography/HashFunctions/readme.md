# Hash functions

|Name                   |   Classes documentation |
|:---------------------:|:-----------------------:|
|Checksums              |[Checksums]              |
|CRC                    |[CRC]                    |
|FunctionAlgorithms     |[FunctionAlgorithms]     |
|Hashes                 |[Hashes]                 |
|KDF                    |[KDF]                    |
|XOF                    |[XOF]                    |


[Checksums]:<./Checksums/>
[CRC]:<./Checksums/>
[FunctionAlgorithms]:<./FunctionAlgorithms/>
[Hashes]:<./Hashes/>
[KDF]:<./KDF/>
[XOF]:<./XOF/>

## Hashes

Summary of the implemented hash functions :

|Name         |Standard          |Documentation        |Status       |
|:-----------:|:----------------:|:-------------------:|:-----------:|
| Poly1305    |[RFC 8439]        |  [Poly1305]         | OK          |
| SHA2-224    |[RFC 6234]        |  [SHA2]             | OK          |
| SHA2-256    |[RFC 6234]        |  [SHA2]             | OK          |
| SHA2-384    |[RFC 6234]        |  [SHA2]             | OK          |
| SHA2-512    |[RFC 6234]        |  [SHA2]             | OK          |
| SHA3-224    |[FIPS 202]        |  [SHA3]             | OK          |
| SHA3-256    |[FIPS 202]        |  [SHA3]             | OK          |  
| SHA3-384    |[FIPS 202]        |  [SHA3]             | OK          |  
| SHA3-512    |[FIPS 202]        |  [SHA3]             | OK          |

### Hashing example

## Checksums

|Name         |Standard          |Documentation        |Status       |
|:-----------:|:----------------:|:-------------------:|:-----------:|
| empty       |   empty          |  empty              | EMPTY       |

## CRC

|Name         |Standard          |Documentation        |Status       |
|:-----------:|:----------------:|:-------------------:|:-----------:|
| empty       |   empty          |  empty              | EMPTY       |

## Function Algorithms


|Name         |Standard          |Documentation        |Status       |
|:-----------:|:----------------:|:-------------------:|:-----------:|
| Keccak      |[FIPS 202]        |  [Keccak]           | TODO        |

[Keccak]:<./keccak.md>

## KDF

|Name         |Standard          |Documentation        |Status       |
|:-----------:|:----------------:|:-------------------:|:-----------:|
| Keccak      |[FIPS 202]        |  [Keccak]           | TODO        |

## XOF (Extendable output functions)

|Name         |Standard          |Documentation        |Status       |
|:-----------:|:----------------:|:-------------------:|:-----------:|
| SHAKE128    |[FIPS 202]        |  [SHAKE128]         | OK          |
| SHAKE256    |[FIPS 202]        |  [SHAKE256]         | OK          |





[Poly1305]:<./poly1305.md>
[SHA2]:<./sha2.md>
[SHA3]:<./sha3.md>

[RFC 8439]:<https://tools.ietf.org/html/rfc8439>
[RFC 6234]:<https://tools.ietf.org/html/rfc6234>
[FIPS 202]:<https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf>

