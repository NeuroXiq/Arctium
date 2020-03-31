## Simple DER decoder

**Arctium.Cryptography.ASN1.Serialization.X690** namespace contains simple ASN.1  
X690 decoders which can be used for decoding serizalized objects.  
For this example, I will take encoded data from wikipedia:
https://en.wikipedia.org/wiki/Abstract_Syntax_Notation_One

```
FooProtocol DEFINITIONS ::= BEGIN

    FooQuestion ::= SEQUENCE {
        trackingNumber INTEGER,
        question       IA5String
    }

    FooAnswer ::= SEQUENCE {
        questionNumber INTEGER,
        answer         BOOLEAN
    }

END
```  

and encoded bytes are: 
```
30 13 02 01 05 16 0e 41 6e 79 62 6f 64 79 20 74 68 65 72 65 3f
```  

```cs
 class Program
    {
        static byte[] encodedData = new byte[] {
            0x30, 0x13, 0x02, 0x01, 0x05, 0x16, 0x0e, 0x41, 0x6e,
            0x79, 0x62, 0x6f, 0x64, 0x79, 0x20, 0x74, 0x68, 0x65, 0x72, 0x65, 0x3f,
        };

        static void Main(string[] args)
        {
            DerDeserializer der = new DerDeserializer();
            X690DecodedNode metadataDecodedNode =  der.Deserialize(encodedData);

            // always perform this step (get first inner result)
            X690DecodedNode decodedBytesRootNode = metadataDecodedNode[0];

            // decodedBytesRootNode contains decoded bytes
            
        }
    }
```


