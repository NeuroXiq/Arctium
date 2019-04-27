namespace Arctium.Connection.Tls.Protocol.RecordProtocol
{
    class TlsGenericStreamCiphertext : Record
    {
        public byte[] Content;
        public byte[] MAC;
    }
}
