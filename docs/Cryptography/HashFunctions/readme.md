# Hash functions


## Hashes

Summary of the implemented hash functions :

|Name         |Standard          |Documentation        |Status       |
|:-----------:|:----------------:|:-------------------:|:-----------:|
|  Poly1305   |[RFC 8439]        |  [Poly1305]         | OK          |
| SHA2-224    |[RFC 6234]        |  [SHA2]             | OK          |
| SHA2-256    |[RFC 6234]        |  [SHA2]             | OK          |
| SHA2-384    |[RFC 6234]        |  [SHA2]             | OK          |
| SHA2-512    |[RFC 6234]        |  [SHA2]             | OK          |
| SHA3-224    |[FIPS 202]        |  [SHA3]             | TODO        |
| SHA3-256    |[FIPS 202]        |  [SHA3]             | TODO        |  
| SHA3-384    |[FIPS 202]        |  [SHA3]             | TODO        |  
| SHA3-512    |[FIPS 202]        |  [SHA3]             | TODO        |


          

[Poly1305]:<./poly1305.md>
[SHA2]:<./sha2.md>
[SHA3]:<./sha3.md>

[RFC 8439]:<https://tools.ietf.org/html/rfc8439>
[RFC 6234]:<https://tools.ietf.org/html/rfc6234>
[FIPS 202]:<https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf>


### Hashing example

Hash functions derive from "HashFunctionBase" which contains basic hashing methods.
Typical hashing schema are below:

```cs
using System;
using System.IO;
using System.Text;
using Arctium.Cryptography.HashFunctions;


namespace DEBUG_ConsoleApplicationForTests
{
    class Program
    {
        static void Main(string[] args)
        {
            HashFunctionBase hashFunction = new SHA224();

            byte[] data1 = new byte[] { 1, 2, 3 };
            byte[] textData = Encoding.ASCII.GetBytes("text data");
            Stream dataStream = new FileStream("C:\\somedata.txt", FileMode.Open);
            byte[] rangeData = new byte[] { 5, 6, 7, 8 };

            //hash some blocks,
            //can mix buffers with streams, all bytes processed in provided orded

            hashFunction.HashBytes(data1);
            hashFunction.HashBytes(textData);
            hashFunction.HashBytes(dataStream);
            hashFunction.HashBytes(rangeData, 1, 2);

            //hash result
            byte[] result = hashFunction.HashFinal();
        }
    }
}

```

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
| empty       |   empty          |  empty              | EMPTY       |


