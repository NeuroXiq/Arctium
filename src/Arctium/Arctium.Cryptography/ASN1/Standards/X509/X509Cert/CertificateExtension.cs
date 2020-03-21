using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;

namespace Arctium.Cryptography.ASN1.Standards.X509.X509Cert
{
    public abstract class CertificateExtension
    {
        public ExtensionType ExtensionType { get; protected set; }
        public bool IsCritical { get; protected set; }
    }
}
