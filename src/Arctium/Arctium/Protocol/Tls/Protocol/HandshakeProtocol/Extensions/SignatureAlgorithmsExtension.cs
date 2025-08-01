using Arctium.Protocol.Tls.Protocol.HandshakeProtocol.Extensions.Enum;

namespace Arctium.Protocol.Tls.Protocol.HandshakeProtocol.Extensions
{
    class SignatureAlgorithmsExtension : HandshakeExtension
    {
        public struct SignatureAndHashAlgorithm
        {
            public HashAlgorithmType HashAlgorithm;
            public SignatureAlgorithm SignatureAlgorithm;

            public SignatureAndHashAlgorithm(HashAlgorithmType hashType, SignatureAlgorithm signatureType)
            {
                HashAlgorithm = hashType;
                SignatureAlgorithm = signatureType;
            }
        }

        public SignatureAndHashAlgorithm[] SignatureAndHashAlgorithmList;

        public SignatureAlgorithmsExtension(SignatureAndHashAlgorithm[] signAndHashList) : base(HandshakeExtensionType.SignatureAlgorithms)
        {
            SignatureAndHashAlgorithmList = signAndHashList;
        }
    }
}
