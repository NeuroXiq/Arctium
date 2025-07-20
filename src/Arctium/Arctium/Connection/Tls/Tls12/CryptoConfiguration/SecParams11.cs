using Arctium.Standards.Connection.Tls.Tls12.CryptoConfiguration;
using Arctium.Standards.Connection.Tls.Protocol;
using Arctium.Standards.Connection.Tls.Protocol.HandshakeProtocol;
using Arctium.Standards.Connection.Tls.Protocol.RecordProtocol;

namespace Arctium.Standards.Connection.Tls.Tls12.CryptoConfiguration
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
