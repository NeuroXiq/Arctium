using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;

namespace Arctium.Cryptography.ASN1.Standards.X509.X509Cert.Extensions
{
    public abstract class CertificateExtension
    {
        public readonly ExtensionType ExtensionType;
        public readonly bool IsCritical;

        protected CertificateExtension(ExtensionType type, bool isCritical)
        {
            ExtensionType = type;
            IsCritical = isCritical;
        }

#if DEBUG
        public override string ToString()
        {
            return this.GetType().Name;
        }
#endif
    }
}
