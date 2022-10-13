

using Arctium.Standards.X509.X509Cert.GenName;

namespace Arctium.Standards.X509.X509Cert.Extensions
{
    public class SubjectAlternativeNamesExtension : CertificateExtension
    {
        public GeneralName[] GeneralNames { get; private set; }

        public SubjectAlternativeNamesExtension(bool isCritical, GeneralName[] generalNames) : base(ExtensionType.SubjectAltName, isCritical)
        {
            GeneralNames = generalNames;
        }
    }
}
