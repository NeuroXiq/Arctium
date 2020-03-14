using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes;

namespace Arctium.Encoding.IDL.ASN1.Standards.X509.X509Certificate
{
    public class X509CertificateExtension
    {
        public X509CertExtensionType ExtensionType { get; private set; }
        public ObjectIdentifier Identifier { get; private set; }
        public bool IsCritical { get; private set; }
    }
}
