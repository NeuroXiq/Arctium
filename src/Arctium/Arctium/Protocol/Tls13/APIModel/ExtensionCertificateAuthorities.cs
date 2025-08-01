namespace Arctium.Protocol.Tls13.APIModel
{
    public class ExtensionCertificateAuthorities : Extension
    {
        public override ExtensionType ExtensionType => ExtensionType.CertificateAuthorities;

        public byte[][] Authorities { get; private set; }

        internal ExtensionCertificateAuthorities(byte[][] authorities)
        {
            Authorities = authorities;
        }
    }
}
