using Arctium.Connection.Tls.CryptoConfiguration;

namespace Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions
{
    class SignatureAlgorithms : HandshakeExtension
    {
        public struct SignatureAndHashAlgorithm
        {
            public HashAlgorithmType HashAlgorithm;
            public SignatureAlgorithm SignatureAlgorithm;
        }

        public SignatureAndHashAlgorithm[] SignatureAndHashAlgorithmList;

        public SignatureAlgorithms(SignatureAndHashAlgorithm[] signAndHashList) : base(HandshakeExtensionType.SignatureAlgorithms)
        {
            SignatureAndHashAlgorithmList = signAndHashList;
        }
    }
}
