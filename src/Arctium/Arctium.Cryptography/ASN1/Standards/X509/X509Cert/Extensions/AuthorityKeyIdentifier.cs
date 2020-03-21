using Arctium.Cryptography.ASN1.Standards.X509.X509Cert.Extensions.GeneralNameDef;

namespace Arctium.Cryptography.ASN1.Standards.X509.X509Cert.Extensions
{
    class AuthorityKeyIdentifier
    {
        public GeneralName[] GeneralNames { get; private set; }
        public byte[] KeyIdentifier { get; private set; }
        public byte[] CertificateSerialNumber { get; private set; }

    }
}
