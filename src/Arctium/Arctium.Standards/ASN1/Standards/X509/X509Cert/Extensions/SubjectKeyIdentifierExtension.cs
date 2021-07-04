namespace Arctium.Standards.ASN1.Standards.X509.X509Cert.Extensions
{
    public class SubjectKeyIdentifierExtension : CertificateExtension
    {
        public byte[] SubjectKeyIdentifier { get; private set; }

        public SubjectKeyIdentifierExtension(bool isCritical, byte[] value) : base(ExtensionType.SubjectKeyIdentifier, isCritical)
        {
            SubjectKeyIdentifier = value;
        }
    }
}
