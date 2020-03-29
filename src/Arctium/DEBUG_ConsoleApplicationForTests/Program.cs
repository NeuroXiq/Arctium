//
// [Testing console program]
// Testing console program exclude from solution.
// Imports all Arctium dll, easy to check how something works
//


using Arctium.Cryptography.ASN1.Standards.X509.X509Cert;
using System;
using System.IO;

namespace DEBUG_ConsoleApplicationForTests
{
    class Program
    {
        static void Main(string[] args)
        {
            new X509CertificateDeserializer().FromPem("d:\\GTSRootR1.crt");
        }
    }
}
