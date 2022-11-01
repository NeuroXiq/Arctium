namespace Arctium.Standards.Connection.Tls.Tls13.Model.Extensions
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
