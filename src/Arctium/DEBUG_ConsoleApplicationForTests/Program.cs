//
// [Testing console program]
// Testing console program exclude from solution.
// Imports all Arctium dll, easy to check how something works
//

using Arctium.Cryptography.Documents.Certificates.X509Certificates.X509v3Certificate;
using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types;
using Arctium.Encoding.IDL.ASN1.Serialization.X690.BER;
using Arctium.Encoding.IDL.ASN1.Serialization.X690.DER;
using Arctium.Encoding.IDL.ASN1.Serialization.Exceptions;
using System.IO;

namespace DEBUG_ConsoleApplicationForTests
{
    class Program
    {
        static void Main(string[] args)
        {
            X509v3CertificateEncoding.FromPem("D:\\GTSRootR1.crt");
        }
    }
}
