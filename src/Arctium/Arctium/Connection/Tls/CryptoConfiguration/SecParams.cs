using Arctium.Connection.Tls.CryptoConfiguration;

namespace Arctium.Connection.Tls.Protocol
{
    ///<summary>security parameters TLS 1.1</summary>
    struct SecParams11
    {
        public RecordCryptoType RecordCryptoType;
        public CompressionMethod CompressionMethod;

        public byte[] MacReadSecret;
        public byte[] MacWriteSecret;
        public byte[] KeyReadSecret;
        public byte[] KeyWriteSecret;
    }
}
