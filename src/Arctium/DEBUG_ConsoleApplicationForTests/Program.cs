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
using Arctium.Encoding.IDL.ASN1.Standards.X509.X509Certificate;

namespace DEBUG_ConsoleApplicationForTests
{
    class Program
    {
        static void Main(string[] args)
        {
            new X509CertificateDeserializer().FromPem("D:\\wikipedia_cert.cer");
        }
    }
}
