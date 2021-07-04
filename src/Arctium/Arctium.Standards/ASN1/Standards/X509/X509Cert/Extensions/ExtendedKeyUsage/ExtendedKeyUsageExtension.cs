namespace Arctium.Standards.ASN1.Standards.X509.X509Cert.Extensions
{
    public class ExtendedKeyUsageExtension : CertificateExtension
    {
        public KeyPurposeId[] KeyUsageSyntax { get; private set; }

        public ExtendedKeyUsageExtension(bool isCritical, KeyPurposeId[] keyUsageSyntax) : base(ExtensionType.ExtendedKeyUsage, isCritical)
        {
            KeyUsageSyntax = keyUsageSyntax;
        }
    }
}
