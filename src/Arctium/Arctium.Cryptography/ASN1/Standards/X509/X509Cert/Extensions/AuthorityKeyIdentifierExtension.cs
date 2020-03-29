
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert.Extensions;

namespace Arctium.Cryptography.ASN1.Standards.X509.X509Cert.Extensions
{
    public class AuthorityKeyIdentifierExtension : CertificateExtension
    {
        public AuthorityKeyIdentifierExtension(bool isCritical, 
            GeneralName[] generalNames, 
            byte[] keyIdentifier, 
            byte[] certificateSerialNumber) : base(ExtensionType.AuthorityKeyIdentifier, isCritical)
        {
            GeneralNames = generalNames;
            KeyIdentifier = keyIdentifier;
            CertificateSerialNumber = certificateSerialNumber;
        }

        public GeneralName[] GeneralNames { get; private set; }
        public byte[] KeyIdentifier { get; private set; }
        public byte[] CertificateSerialNumber { get; private set; }

    }
}
