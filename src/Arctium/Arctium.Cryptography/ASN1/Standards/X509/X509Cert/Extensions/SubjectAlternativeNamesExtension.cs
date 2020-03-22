using Arctium.Cryptography.ASN1.Standards.X509.Types;

namespace Arctium.Cryptography.ASN1.Standards.X509.X509Cert.Extensions
{
    public class SubjectAlternativeNamesExtension : CertificateExtension
    {
        public GeneralName[] GeneralNames { get; private set; }

        public SubjectAlternativeNamesExtension(bool isCritical, GeneralName[] generalNames) : base(ExtensionType.SubjectAlternativeName, isCritical)
        {
            GeneralNames = generalNames;
        }
    }
}
