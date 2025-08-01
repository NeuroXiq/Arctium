using Arctium.Protocol.Tls13Impl.Model;

namespace Arctium.Protocol.Tls13Impl.Model.Extensions
{
    internal class CertificateAuthoritiesExtension : Extension
    {
        public byte[][] Authorities { get; private set; }

        public override ExtensionType ExtensionType => ExtensionType.CertificateAuthorities;

        public CertificateAuthoritiesExtension(byte[][] authorities)
        {
            Authorities = authorities;
        }
    }
}
