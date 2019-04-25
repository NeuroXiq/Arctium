namespace Arctium.Connection.Tls.Protocol.HandshakeProtocol
{
    class SessionID
    {
        public byte[] ID;

        public SessionID(byte[] bytes)
        {
            ID = bytes;
        }
    }
}
