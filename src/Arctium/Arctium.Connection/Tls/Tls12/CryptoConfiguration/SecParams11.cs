using Arctium.Connection.Tls.Tls12.CryptoConfiguration;
using Arctium.Connection.Tls.Protocol;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;
using Arctium.Connection.Tls.Protocol.RecordProtocol;

namespace Arctium.Connection.Tls.Tls12.CryptoConfiguration
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
