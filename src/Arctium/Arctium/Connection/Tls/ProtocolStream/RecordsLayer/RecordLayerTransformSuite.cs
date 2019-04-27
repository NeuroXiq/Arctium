using Arctium.Connection.Tls.Protocol.HandshakeProtocol;
using Arctium.Connection.Tls.Protocol.RecordProtocol;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer
{
    class RecordLayerTransformSuite
    {
        public CipherSuite[] Ciphers { get; private set; }
        public CompressionMethod[] CompressionMethods { get; private set; }

        public RecordLayerTransformSuite()
        {
            Ciphers = new CipherSuite[]
            {
                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA
            };

            CompressionMethods = new CompressionMethod[]
            {
                CompressionMethod.NULL
            };
        }
    }
}
