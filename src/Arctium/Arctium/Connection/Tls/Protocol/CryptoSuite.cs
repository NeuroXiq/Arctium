using Arctium.Connection.Tls.Protocol.HandshakeProtocol;
using Arctium.Connection.Tls.Protocol.RecordProtocol;

namespace Arctium.Connection.Tls.Protocol
{
    ///<summary>Object oriented 'CipherSuite'</summary>
    class CryptoSuite
    {
        public CipherSuite CipherSuiteBase;

        public KeyExchangeAlgorithm KeyExchangeAlgorithm;
        public RecordCryptoType RecordCryptoType;
        public CompressionMethod CompressionMethod;
    }
}
