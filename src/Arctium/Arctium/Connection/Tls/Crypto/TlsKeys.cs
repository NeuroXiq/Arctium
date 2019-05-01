namespace Arctium.Connection.Tls.Crypto
{
    struct TlsKeys
    {
        public byte[] ClientWriteMacSecret;
        public byte[] ServerWriteMacSecret;
        public byte[] ClientWriteKey;
        public byte[] ServerWriteKey;
    }
}
