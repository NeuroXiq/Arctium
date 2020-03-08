//
// [Testing console program]
// Testing console program exclude from solution.
// Imports all Arctium dll, easy to check how something works
//

using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types;
using Arctium.Encoding.IDL.ASN1.Serialization.X690.BER;
using Arctium.Encoding.IDL.ASN1.Serialization.X690.DER;
using Arctium.Encoding.IDL.ASN1.Serialization.Exceptions;
using System.IO;
using Arctium.Cryptography.Documents.Certificates.X509Certificates;

namespace DEBUG_ConsoleApplicationForTests
{
    class Program
    {
        static void Main(string[] args)
        {
            new X509CertDecoder().FromPem("D:\\wikipedia_cert.cer");
        }
    }
}
