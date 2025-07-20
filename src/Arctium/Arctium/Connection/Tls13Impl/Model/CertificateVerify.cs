using static Arctium.Standards.Connection.Tls13Impl.Model.Extensions.SignatureSchemeListExtension;

namespace Arctium.Standards.Connection.Tls13Impl.Model
{
    internal class CertificateVerify
    {
        public SignatureScheme SignatureScheme { get; private set; }
        public byte[] Signature { get; private set; }

        public CertificateVerify(SignatureScheme scheme, byte[] signature)
        {
            SignatureScheme = scheme;
            Signature = signature;
        }

    }
}
