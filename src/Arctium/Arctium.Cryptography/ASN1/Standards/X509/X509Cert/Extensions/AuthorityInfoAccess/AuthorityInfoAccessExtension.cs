namespace Arctium.Cryptography.ASN1.Standards.X509.X509Cert.Extensions
{
    public class AuthorityInfoAccessExtension : CertificateExtension
    {
        public AccessDescription[] AuthorityInfoAccessSyntax { get; private set; }

        public AuthorityInfoAccessExtension(AccessDescription[] accessDescriptions, bool isCritical) : 
            base(ExtensionType.AuthorityInfoAccess, isCritical)
        {
            AuthorityInfoAccessSyntax = accessDescriptions;
        }
    }
}
