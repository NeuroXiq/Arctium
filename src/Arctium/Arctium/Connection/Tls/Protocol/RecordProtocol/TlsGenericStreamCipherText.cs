namespace Arctium.Connection.Tls.Protocol.RecordProtocol
{
    class TlsGenericStreamCipherText : Record
    {
        public byte[] Content;
        public byte[] MAC;
    }
}
