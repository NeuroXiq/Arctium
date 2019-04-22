namespace Arctium.Connection.Tls.RecordProtocol
{
    class TlsGenericBlockCipherText : Record
    {
        public byte[] IV;
        public byte[] Content;
        public byte[] MAC;
        public byte[] Padding;
        public byte PaddingLength;
    }
}
