namespace Arctium.Connection.Tls.CryptoFunctions
{
    struct Tls11KeyBlock
    {
        public byte[] ClientWriteMacSecret;
        public byte[] ServerWriteMacSecret;
        public byte[] ClientWriteKey;
        public byte[] ServerWriteKey;
    }
}
