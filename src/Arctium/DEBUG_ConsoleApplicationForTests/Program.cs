//
// [Testing console program]
// Testing console program exclude from solution.
// Imports all Arctium dll, easy to check how something works
//


using Arctium.Cryptography.ASN1.Serialization.X690;
using Arctium.Cryptography.ASN1.Serialization.X690.DER;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert;
using System;
using System.IO;

namespace DEBUG_ConsoleApplicationForTests
{
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
}
