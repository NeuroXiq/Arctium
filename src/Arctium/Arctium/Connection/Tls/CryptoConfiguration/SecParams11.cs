using Arctium.Connection.Tls.CryptoConfiguration;
using Arctium.Connection.Tls.Protocol.RecordProtocol;

namespace Arctium.Connection.Tls.Protocol
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
