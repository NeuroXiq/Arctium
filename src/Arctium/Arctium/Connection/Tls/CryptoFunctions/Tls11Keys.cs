namespace Arctium.Connection.Tls.CryptoFunctions
{
    struct Tls11Keys
    {
        public byte[] ClientWriteMacSecret;
        public byte[] ServerWriteMacSecret;
        public byte[] ClientWriteKey;
        public byte[] ServerWriteKey;
    }
}
