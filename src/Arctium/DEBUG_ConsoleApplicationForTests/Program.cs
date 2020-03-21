//
// [Testing console program]
// Testing console program exclude from solution.
// Imports all Arctium dll, easy to check how something works
//


using Arctium.Cryptography.ASN1.Standards.X509.X509Cert;

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
