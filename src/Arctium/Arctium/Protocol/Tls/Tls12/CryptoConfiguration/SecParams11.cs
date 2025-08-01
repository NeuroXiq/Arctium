using Arctium.Protocol.Tls.Tls12.CryptoConfiguration;
using Arctium.Protocol.Tls.Protocol;
using Arctium.Protocol.Tls.Protocol.HandshakeProtocol;
using Arctium.Protocol.Tls.Protocol.RecordProtocol;

namespace Arctium.Protocol.Tls.Tls12.CryptoConfiguration
{
    ///<summary>security parameters TLS 1.1</summary>
    struct SecParams11
    {
        public RecordCryptoType RecordCryptoType;
        public CompressionMethod CompressionMethod;

        public byte[] MacReadKey;
        public byte[] MacWriteKey;
        public byte[] BulkReadKey;
        public byte[] BulkWriteKey;
        public byte[] MasterSecret;
    }
}
