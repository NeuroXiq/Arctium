## Hash functions

Summary of the implemented hash functions :

|Name         |Standard          |Documentation        |Status       |
|:-----------:|:----------------:|:-------------------:|:-----------:|
|  Poly1305   |[RFC 8439]        |  [Poly1305]         | OK          |
| SHA-224     |[RFC 4634]        |  [SHA-224]          | OK          |
| SHA-256     |[RFC 4634]        |  [SHA-256]          | OK          |
| SHA-384     |[RFC 4634]        |  [SHA-384]          | OK          |
| SHA-512     |[RFC 4634]        |  [SHA-512]          | OK          |

[Poly1305]:<./poly1305.md>
[SHA-224]:<./sha224.md>
[SHA-256]:<./sha256.md>
[SHA-384]:<./sha384.md>
[SHA-512]:<./sha512.md>

[RFC 8439]:<https://tools.ietf.org/html/rfc8439>
[RFC 4634]:<https://tools.ietf.org/html/rfc4634#section-4.1>


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


