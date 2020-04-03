//
// [Testing console program]
// Testing console program exclude from solution.
// Imports all Arctium dll, easy to check how something works
//


using Arctium.Cryptography.ASN1.Standards.X501.Types;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert.Extensions;
using Arctium.Cryptography.FileFormat.PEM;
using System;
using System.IO;

namespace DEBUG_ConsoleApplicationForTests
{
    class Program
    {

        static void Main(string[] args)
        {
            // certificate deserializer
            X509CertificateDeserializer deserializer = new X509CertificateDeserializer();

            // Certificate can be decoded in following manner:

            // From Raw Bytes
            byte[] certificateBytes = File.ReadAllBytes("C:\\some_certificate.cer");
            X509Certificate certificateFromRawBytes = deserializer.FromBytes(certificateBytes);

            // From PEM file

            X509Certificate certificateFromPem = deserializer.FromPem("C:\\some_pem.crt");
            
            // Or first decode pem and the raw bytes

            PemFile pemFile = PemFile.FromFile("D:\\some_pem.crt");
            byte[] decodedPemBytes = pemFile.DecodedData;

            //X509Certificate certificateFromPemToBytes = deserializer.FromBytes(decodedPemBytes);


            // Now object is created, examples usage:
            var cert = certificateFromRawBytes;

            Console.WriteLine(cert.ValidNotAfter);
            Console.WriteLine(cert.ValidNotBefore);
            Console.WriteLine(cert.Version);

            RelativeDistinguishedName[] relativeDistinguishedNames = cert.Subject.GetAsRelativeDistinguishedNames();
            Console.WriteLine("Relative distinguished names:");
            foreach (var rdn in relativeDistinguishedNames)
            {
                foreach (var atv in rdn.AttributeTypeAndValues)
                {
                    AttributeType attributeType = atv.Type;
                    string attributeValue = atv.StringValue();
                    Console.WriteLine(" " + attributeType.ToString() + "=" + attributeValue);
                }
            }

            Console.WriteLine("======== extensions =========");

            CertificateExtension[] extensions = cert.Extensions;
            foreach (var ext in extensions)
            {
                Console.WriteLine("Extensions type: " + ext.ExtensionType.ToString());
                switch (ext.ExtensionType)
                {
                    case ExtensionType.SubjectAltName:
                        SubjectAlternativeNamesExtension altName = (SubjectAlternativeNamesExtension)ext;
                        GeneralName[] generalNames = altName.GeneralNames;
                        Console.WriteLine("General names:");
                        foreach (var gn in generalNames)
                        {
                            Console.WriteLine("  " + gn.ToString());
                        }
                        break;
                    case ExtensionType.Unknown:
                        break;
                    case ExtensionType.ExtendedKeyUsage:
                        break;
                    case ExtensionType.KeyUsage:
                        break;
                    case ExtensionType.SubjectKeyIdentifier:
                        break;
                    // and others ....
                }
            }

        }
    }
}
