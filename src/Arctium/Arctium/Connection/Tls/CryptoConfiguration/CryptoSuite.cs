using Arctium.Connection.Tls.CryptoConfiguration;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;

namespace Arctium.Connection.Tls.Protocol
{
    ///<summary>Object oriented 'CipherSuite'</summary>
    class CryptoSuite
    {
        public CipherSuite CipherSuiteBase;

        public KeyExchangeAlgorithm KeyExchangeAlgorithm;
        public RecordCryptoType RecordCryptoType;

        public CryptoSuite(
            CipherSuite baseSuite,
            KeyExchangeAlgorithm keyExchangeAlgorithm,
            RecordCryptoType recordCryptoType)
        {
            CipherSuiteBase = baseSuite;
            KeyExchangeAlgorithm = keyExchangeAlgorithm;
            RecordCryptoType = recordCryptoType;
        }

    }
}
