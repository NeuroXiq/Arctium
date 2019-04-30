using Arctium.Connection.Tls.Protocol.RecordProtocol;

namespace Arctium.Connection.Tls.Protocol
{
    ///<summary>security parameters v2</summary>
    struct SecParams
    {
        public RecordCryptoType RecordCryptoType;
        public CompressionMethod CompressionMethod;

        public byte[] MacReadSecret;
        public byte[] MacWriteSecret;
        public byte[] KeyReadSecret;
        public byte[] KeyWriteSecret;
    }
}
