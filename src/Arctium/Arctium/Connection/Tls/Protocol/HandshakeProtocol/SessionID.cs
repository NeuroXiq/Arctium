using System;
namespace Arctium.Connection.Tls.Protocol.HandshakeProtocol
{
    class SessionID
    {
        public byte[] ID { get; private set; }
        public byte Length { get { return (byte)ID.Length; } }

        public SessionID(byte[] bytes)
        {
                
            ID = bytes;
        }
    }
}
