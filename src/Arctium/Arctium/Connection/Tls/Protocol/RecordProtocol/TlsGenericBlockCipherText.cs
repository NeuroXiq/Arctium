namespace Arctium.Connection.Tls.Protocol.RecordProtocol
{
    class TlsGenericBlockCiphertext : Record
    {
        public byte[] IV;
        public byte[] Content;
        public byte[] MAC;
        public byte[] Padding;
        public byte PaddingLength;
    }
}
