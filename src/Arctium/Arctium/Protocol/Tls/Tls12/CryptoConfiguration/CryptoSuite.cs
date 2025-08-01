using Arctium.Protocol.Tls.Tls12.CryptoConfiguration;
using Arctium.Protocol.Tls.Protocol.HandshakeProtocol;
using Arctium.Protocol.Tls.Protocol.HandshakeProtocol.Extensions.Enum;

namespace Arctium.Protocol.Tls.Protocol
{
    ///<summary>Object oriented 'CipherSuite'</summary>
    class CryptoSuite
    {
        public CipherSuite CipherSuiteBase;

        public KeyExchangeAlgorithm KeyExchangeAlgorithm;
        public SignatureAlgorithm SigningAlgorithm;
        public RecordCryptoType RecordCryptoType;

        public CryptoSuite(
            CipherSuite baseSuite,
            KeyExchangeAlgorithm keyExchangeAlgorithm,
            SignatureAlgorithm signAlgorithm,
            RecordCryptoType recordCryptoType)
        {
            CipherSuiteBase = baseSuite;
            KeyExchangeAlgorithm = keyExchangeAlgorithm;
            RecordCryptoType = recordCryptoType;
            SigningAlgorithm = signAlgorithm;
        }

    }
}
