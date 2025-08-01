namespace Arctium.Protocol.Tls.Tls12.CryptoFunctions
{
    struct Tls11KeyBlock
    {
        public byte[] ClientWriteMacSecret;
        public byte[] ServerWriteMacSecret;
        public byte[] ClientWriteKey;
        public byte[] ServerWriteKey;
    }
}
